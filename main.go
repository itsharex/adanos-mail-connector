package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	md "github.com/JohannesKaufmann/html-to-markdown"
	"github.com/JohannesKaufmann/html-to-markdown/plugin"
	"github.com/PuerkitoBio/goquery"
	"github.com/mhale/smtpd"
	"github.com/mylxsw/adanos-alert/pkg/connector"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/pattern"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"

func main() {

	app := &cli.App{
		Name:    "adanos-mail-connector",
		Usage:   "adanos-mail-connector 可以伪装成为 SMTP 服务器，将邮件转换为 Adanos 事件发送给 Adanos-alert Server",
		Version: fmt.Sprintf("%s (%s)", Version, GitCommit[:8]),
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "adanos-server",
				Usage: "adanos-alert server addr",
			},
			&cli.StringFlag{
				Name:  "adanos-token",
				Value: "",
				Usage: "adanos-alert server token",
			},
			&cli.StringSliceFlag{
				Name:  "tag",
				Usage: "specify tags for alert message",
			},
			&cli.StringFlag{
				Name:  "smtp-listen",
				Value: "127.0.0.1:2525",
				Usage: "SMTP 服务器监听地址",
			},
			&cli.BoolFlag{
				Name:  "html2md",
				Usage: "是否将 HTML 内容转换为 Markdown",
			},
			&cli.StringFlag{
				Name:  "origin",
				Value: "adanos-mail-connector",
				Usage: "Adanos 事件来源标识",
			},
			&cli.StringFlag{
				Name:  "exclude-fliters",
				Usage: "邮件排除规则配置文件，格式为 YAML",
				Value: "",
			},
		},
		Action: func(c *cli.Context) error {
			adanosServers := c.StringSlice("adanos-server")
			if len(adanosServers) == 0 {
				adanosServers = append(adanosServers, "http://localhost:19999")
			}

			adanosToken := c.String("adanos-token")
			tags := c.StringSlice("tag")
			html2markdown := c.Bool("html2md")
			origin := c.String("origin")

			excludeFilter := buildExcludeFilters(c.String("exclude-fliters"))

			log.WithFields(log.Fields{
				"version": Version,
				"git":     GitCommit,
			}).Debugf("adanos-mail-connector started")

			return smtpd.ListenAndServe(
				c.String("smtp-listen"),
				buildMailHandler(adanosServers, adanosToken, tags, origin, html2markdown, excludeFilter),
				"mail-handler",
				"",
			)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Errorf("error: %v", err)
		panic(err)
	}
}

// buildExcludeFilters 创建排除规则过滤器
func buildExcludeFilters(conf string) func(data MailContent) bool {
	if conf == "" {
		return func(data MailContent) bool {
			return false
		}
	}

	confData, err := ioutil.ReadFile(conf)
	if err != nil {
		panic(err)
	}

	var filters []ExcludeFilter
	if err := yaml.Unmarshal(confData, &filters); err != nil {
		panic(err)
	}

	return func(data MailContent) bool {
		for _, filter := range filters {
			matched, err := pattern.Match(filter.Expr, data)
			if err != nil {
				log.WithFields(log.Fields{
					"data":   data,
					"filter": filter,
				}).Errorf("pattern matche failed: %v", err)
				continue
			}

			if matched {
				return true
			}
		}

		return false
	}
}

// ExcludeFilter 排除过滤器
type ExcludeFilter struct {
	Name string `yaml:"name,omitempty"`
	Expr string `yaml:"expr"`
}

// buildMailHandler 创建邮件处理器
func buildMailHandler(adanosServer []string, adanosToken string, tags []string, origin string, html2markdown bool, excludeFilter func(data MailContent) bool) func(origin net.Addr, from string, to []string, data []byte) {
	alerter := buildAdanosAlerter(adanosServer, adanosToken, tags, origin)
	return func(origin net.Addr, from string, to []string, data []byte) {
		msg, err := mail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			log.Errorf("read message from mail failed: %v", err)
			return
		}

		msgID := msg.Header.Get("Message-ID")
		log.Debugf("%s new mail received: %s -> %s", msgID, from, strings.Join(to, ","))

		defer func() {
			if err := recover(); err != nil {
				log.Errorf("%s mail handled with panic: %v", msgID, err)
			}
			log.Debugf("%s mail handled", msgID)
		}()

		bodyReader := msg.Body
		if msg.Header.Get("Content-Transfer-Encoding") == "quoted-printable" {
			bodyReader = quotedprintable.NewReader(msg.Body)
		}

		body, err := ioutil.ReadAll(bodyReader)
		if err != nil {
			log.Errorf("%s read body from body-reader failed: %v", msgID, err)
			return
		}

		mailContent := MailContent{
			Origin:  origin.String(),
			ID:      strings.Trim(msgID, "<>"),
			Subject: msg.Header.Get("Subject"),
			From:    from,
			To:      to,
			Links:   extractLinks(string(body)),
		}

		if excludeFilter(mailContent) {
			log.With(mailContent).Debug("event was dropped because exclude filter matched")
			return
		}

		if html2markdown {
			mailContent.Body = formatAsMarkdown(string(body))
		} else {
			mailContent.Body = string(body)
		}

		log.With(mailContent).Debugf("%s mail received", msgID)
		if err := alerter(mailContent); err != nil {
			log.Errorf("%s send event to adanos server failed: %v", msgID, err)
		}
	}
}

// MailContent 邮件内容对象
type MailContent struct {
	pattern.Helpers
	ID      string            `json:"id"`
	Origin  string            `json:"origin"`
	Subject string            `json:"subject"`
	Body    string            `json:"body"`
	From    string            `json:"from"`
	To      []string          `json:"to"`
	Links   map[string]string `json:"links"`
}

// buildAdanosAlerter 创建报警
func buildAdanosAlerter(adanosServers []string, adanosToken string, tags []string, origin string) func(mailContent MailContent) error {
	adanosConn := connector.NewConnector(adanosToken, adanosServers...)

	return func(mailContent MailContent) error {
		evt := connector.NewEvent(mailContent.Body).
			WithMeta("mail-id", mailContent.ID).
			WithMeta("mail-subject", mailContent.Subject).
			WithMeta("mail-from", mailContent.From).
			WithMeta("mail-to", mailContent.To).
			WithMeta("mail-origin", mailContent.Origin).
			WithMeta("mail-links", mailContent.Links).
			WithOrigin(origin).
			WithTags(tags...)

		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		return adanosConn.Send(ctx, evt)
	}
}

// extractLinks extract links from body
func extractLinks(body string) map[string]string {
	links := make(map[string]string)
	doc, err := goquery.NewDocumentFromReader(bytes.NewBufferString(body))
	if err != nil {
		log.Errorf("ERROR: create body dom object failed: %v", err)
		return links
	}

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		linkURL := s.AttrOr("href", "")
		if strings.HasPrefix(linkURL, "http://") || strings.HasPrefix(linkURL, "https://") {
			links[s.Text()] = linkURL
		}
	})

	return links
}

// formatAsMarkdown 将 html 格式化为 Markdown 格式
func formatAsMarkdown(html string) string {
	converter := md.NewConverter("", true, nil)
	converter.Use(plugin.GitHubFlavored())

	markdown, err := converter.ConvertString(html)
	if err != nil {
		return html
	}

	return markdown
}
