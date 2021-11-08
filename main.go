package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/DusanKasan/parsemail"
	md "github.com/JohannesKaufmann/html-to-markdown"
	"github.com/JohannesKaufmann/html-to-markdown/plugin"
	"github.com/PuerkitoBio/goquery"
	"github.com/mhale/smtpd"
	"github.com/mylxsw/adanos-alert/pkg/connector"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/pattern"
	"github.com/urfave/cli"
	"gopkg.in/gomail.v2"
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
				Name:  "filters",
				Usage: "邮件转发规则配置文件，格式为 YAML，如果没有指定规则，则默认为全部转发",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "relay-strategy",
				Usage: "邮件转发策略：none/dropped/all",
				Value: "none",
			},
			&cli.StringFlag{
				Name:  "relay-host",
				Usage: "邮件转发中继服务器主机地址",
				Value: "",
			},
			&cli.IntFlag{
				Name:  "relay-port",
				Usage: "邮件转发中继服务器主机端口",
				Value: 25,
			},
			&cli.StringFlag{
				Name:  "relay-username",
				Usage: "邮件转发中继服务器账号",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "relay-password",
				Usage: "邮件转发中继服务器密码",
				Value: "",
			},
			&cli.BoolFlag{
				Name:  "relay-ssl",
				Usage: "邮件转发中继服务器是否使用 SSL",
			},
		},
		Action: func(c *cli.Context) error {
			conf := buildConfig(c)
			excludeFilter := buildFilters(conf.FilterConf)

			log.WithFields(log.Fields{
				"version": Version,
				"git":     GitCommit,
			}).Debugf("adanos-mail-connector started")

			return createSMTPServer(
				conf.SMTPListen,
				buildMailHandler(conf, excludeFilter),
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

func buildConfig(c *cli.Context) Config {
	adanosServers := c.StringSlice("adanos-server")
	if len(adanosServers) == 0 {
		adanosServers = append(adanosServers, "http://localhost:19999")
	}

	conf := Config{
		AdanosServers: adanosServers,
		AdanosToken:   c.String("adanos-token"),
		Tags:          c.StringSlice("tag"),
		HTML2Markdown: c.Bool("html2md"),
		Origin:        c.String("origin"),
		FilterConf:    c.String("filters"),
		SMTPListen:    c.String("smtp-listen"),
		RelayStrategy: c.String("relay-strategy"),
		RelayHost:     c.String("relay-host"),
		RelayPort:     c.Int("relay-port"),
		RelayUsername: c.String("relay-username"),
		RelayPassword: c.String("relay-password"),
		RelaySSL:      c.Bool("relay-ssl"),
	}

	if conf.RelayStrategy == "" {
		conf.RelayStrategy = "none"
	}

	if !str.In(conf.RelayStrategy, []string{"none", "dropped", "all"}) {
		panic(fmt.Errorf("invalid relay-strategy, only support none/dropped/all"))
	}

	return conf
}

// Config 配置对象
type Config struct {
	AdanosServers []string
	AdanosToken   string
	Tags          []string
	HTML2Markdown bool
	Origin        string
	FilterConf    string
	SMTPListen    string

	RelayStrategy string
	RelayHost     string
	RelayPort     int
	RelayUsername string
	RelayPassword string
	RelaySSL      bool
}

// createSMTPServer create a SMTP Server
func createSMTPServer(addr string, handler smtpd.Handler, appname string, hostname string) error {
	server := &smtpd.Server{Addr: addr, Handler: handler, Appname: appname, Hostname: hostname}
	server.AuthHandler = func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
		return true, nil
	}
	server.AuthMechs = map[string]bool{
		"LOGIN":    true,
		"PLAIN":    true,
		"CRAM-MD5": true,
	}
	//server.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return server.ListenAndServe()
}

// buildFilters 创建转发规则过滤器
func buildFilters(conf string) func(data MailContent) bool {
	if conf == "" {
		return func(data MailContent) bool {
			return true
		}
	}

	confData, err := ioutil.ReadFile(conf)
	if err != nil {
		panic(err)
	}

	var filters []Filter
	if err := yaml.Unmarshal(confData, &filters); err != nil {
		panic(err)
	}

	return func(data MailContent) bool {
		if len(filters) == 0 {
			return true
		}

		for _, filter := range filters {
			matched, err := pattern.Match(filter.Expr, data)
			if err != nil {
				log.WithFields(log.Fields{
					"data":   data,
					"filter": filter,
				}).Errorf("pattern match failed: %v", err)
				continue
			}

			if matched {
				return true
			}
		}

		return false
	}
}

// Filter 过滤器
type Filter struct {
	Name string `yaml:"name,omitempty"`
	Expr string `yaml:"expr"`
}

// buildMailHandler 创建邮件处理器
func buildMailHandler(conf Config, filter func(data MailContent) bool) func(origin net.Addr, from string, to []string, data []byte) {
	alerter := buildAdanosAlerter(conf.AdanosServers, conf.AdanosToken, conf.Tags, conf.Origin)

	var relayMailSend RelayMailSender

	switch conf.RelayStrategy {
	case "none":
		relayMailSend = func(mailContent MailContent) error { return nil }
	case "all":
		fallthrough
	case "dropped":
		relayMailSend = buildRelayMailSender(conf)
	default:
		panic("invalid relay strategy")
	}

	return func(origin net.Addr, from string, to []string, data []byte) {
		msg, err := parsemail.Parse(bytes.NewReader(data))
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

		mailContent := MailContent{
			msg:     msg,
			data:    data,
			Origin:  origin.String(),
			ID:      strings.Trim(msgID, "<>"),
			Subject: msg.Subject,
			From:    from,
			To:      to,
			Links:   extractLinks(strings.Join([]string{msg.HTMLBody, msg.TextBody}, "\n")),
			Body:    strings.Join([]string{msg.HTMLBody, msg.TextBody}, "\n"),
		}

		matched := filter(mailContent)

		relay := false
		switch conf.RelayStrategy {
		case "all":
			relay = true
		case "dropped":
			if !matched {
				relay = true
			}
		}

		if relay {
			if err := relayMailSend(mailContent); err != nil {
				log.With(mailContent).Errorf("relay mail send failed: %v", err)
			}
		}

		if !matched {
			log.With(mailContent).Debug("event was dropped because exclude filter matched")
			return
		}

		if conf.HTML2Markdown {
			mailContent.Body = formatAsMarkdown(msg.HTMLBody + msg.TextBody)
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
	msg     parsemail.Email
	data    []byte
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
			title := strings.TrimSpace(s.Text())
			if title != "" {
				links[title] = linkURL
			}
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

// RelayMailSender 邮件转发中继
type RelayMailSender func(mailContent MailContent) error

// buildRelayMailSender 创建邮件转发中继
func buildRelayMailSender(conf Config) RelayMailSender {
	dialer := gomail.NewDialer(conf.RelayHost, conf.RelayPort, conf.RelayUsername, conf.RelayPassword)
	dialer.SSL = conf.RelaySSL

	return func(mailContent MailContent) error {
		tos := make([]string, 0)
		for _, t := range mailContent.msg.To {
			tos = append(tos, t.Address)
		}

		ccs := make([]string, 0)
		for _, t := range mailContent.msg.Cc {
			ccs = append(ccs, t.Address)
		}

		message := gomail.NewMessage()
		message.SetHeader("From", conf.RelayUsername)
		message.SetHeader("To", tos...)
		message.SetHeader("Subject", mailContent.msg.Subject)
		if len(ccs) > 0 {
			message.SetHeader("Cc", ccs...)
		}

		if mailContent.msg.HTMLBody == "" {
			message.SetBody(mailContent.msg.ContentType, mailContent.msg.TextBody)
		} else {
			message.SetBody(mailContent.msg.ContentType, mailContent.msg.HTMLBody)
		}

		return dialer.DialAndSend(message)
	}
}

// loginAuth is an smtp.Auth that implements the LOGIN authentication mechanism.
type loginAuth struct {
	username string
	password string
	host     string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		advertised := false
		for _, mechanism := range server.Auth {
			if mechanism == "LOGIN" {
				advertised = true
				break
			}
		}
		if !advertised {
			return "", nil, fmt.Errorf("gomail: unencrypted connection")
		}
	}
	if server.Name != a.host {
		return "", nil, fmt.Errorf("gomail: wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}

	switch {
	case bytes.Equal(fromServer, []byte("Username:")):
		return []byte(a.username), nil
	case bytes.Equal(fromServer, []byte("Password:")):
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("gomail: unexpected server challenge: %s", fromServer)
	}
}
