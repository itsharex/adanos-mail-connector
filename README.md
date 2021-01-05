# adanos-mail-connector

伪装成为 SMTP 服务器，将邮件转换为 Adanos 事件发送给 Adanos-alert Server


```go
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
```

事件排除规则，以 MailContent 对象为参数。事件排除规则配置文件格式为 YAML

```yaml
- name: 用于描述该规则
  expr: Origin == "192.168.1.212:25"
- name: 规则 2
  expr: any(To, {# matches "mylxsw@aicode.cc"})
```