// Package alert routes incidents to the configured channels: a loud console
// banner, a JSONL log, syslog and an optional webhook. Notification must
// never block detection: every channel failure is contained.
package alert

import (
        "bytes"
        "encoding/json"
        "fmt"
        "net"
        "net/http"
        "os"
        "strings"
        "time"
)

// Incident is one detected tamper event.
type Incident struct {
        Time    time.Time `json:"time"`
        Source  string    `json:"source"` // fsnotify | integrity
        Path    string    `json:"path"`
        Profile string    `json:"profile"`
        Kind    string    `json:"kind"`
        Token   string    `json:"token"`
        Detail  string    `json:"detail"`
        PID     int       `json:"pid,omitempty"`
        Proc    string    `json:"proc,omitempty"`
}

// Router emits incidents to every enabled channel.
type Router struct {
        Console       bool
        JSONL         bool
        JSONLPath     string
        Syslog        bool
        WebhookURL    string
        webhookFailed bool
}

// New builds a router from config.
func New(console, jsonl bool, jsonlPath string, syslog bool, webhook string) *Router {
        return &Router{
                Console:    console,
                JSONL:      jsonl,
                JSONLPath:  jsonlPath,
                Syslog:     syslog,
                WebhookURL: webhook,
        }
}

const banner = `
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 !!  HELLHOUND - CANARY BITTEN                  !!
 !!  decoy tampering detected: %s
 !!  %s
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`

// Emit delivers inc to all configured channels.
func (r *Router) Emit(inc Incident) {
        if r.Console {
                detail := fmt.Sprintf("profile=%s kind=%s via=%s", inc.Profile, inc.Kind, inc.Source)
                if inc.PID != 0 {
                        detail += fmt.Sprintf(" writer: pid %d (%s)", inc.PID, inc.Proc)
                }
                fmt.Fprintf(os.Stderr, "\033[1;31m%s\033[0m\n", fmt.Sprintf(banner, inc.Path, detail))
        }
        if r.JSONL {
                r.emitJSONL(inc)
        }
        if r.Syslog {
                r.emitSyslog(inc)
        }
        if r.WebhookURL != "" {
                r.emitWebhook(inc)
        }
}

func (r *Router) emitJSONL(inc Incident) {
        f, err := os.OpenFile(r.JSONLPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
        if err != nil {
                return
        }
        defer f.Close()
        line, err := json.Marshal(inc)
        if err != nil {
                return
        }
        f.Write(append(line, '\n'))
}

func (r *Router) emitSyslog(inc Incident) {
        // Best effort RFC3164-ish datagram to the local socket. Failure is
        // non-fatal: not every system runs a syslog daemon.
        sock, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: "/dev/log", Net: "unixgram"})
        if err != nil {
                return
        }
        defer sock.Close()
        msg := fmt.Sprintf("<13>hellhound: canary bitten source=%s path=%s profile=%s kind=%s token=%s",
                inc.Source, inc.Path, inc.Profile, inc.Kind, inc.Token)
        sock.Write([]byte(msg))
}

func (r *Router) emitWebhook(inc Incident) {
        body, err := json.Marshal(inc)
        if err != nil {
                return
        }
        client := &http.Client{Timeout: 5 * time.Second}
        resp, err := client.Post(r.WebhookURL, "application/json", bytes.NewReader(body))
        if err != nil {
                // Report once per run; a dead webhook must not spam stderr.
                if !r.webhookFailed {
                        r.webhookFailed = true
                        fmt.Fprintf(os.Stderr, "hellhound: webhook unreachable: %v\n", err)
                }
                return
        }
        resp.Body.Close()
}

// Summarize renders a human-readable one-liner for listings.
func Summarize(inc Incident) string {
        s := strings.ReplaceAll(inc.Time.Format("2006-01-02 15:04:05"), "T", " ")
        return fmt.Sprintf("%s  %-9s %-12s %s", s, inc.Source, inc.Kind, inc.Path)
}
