// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import (
	"strings"
	"testing"
)

// A webhook URL inside an error string is still a credential.
//
// Go's net/http puts the full request URL into transport errors, and a
// Discord or Slack webhook carries its secret in the path. That string
// was persisted as Channel.LastError — in a field the secret codec
// does not seal — and served to viewers through the alert-event
// history and the audit log.

func TestRedactURLsInText(t *testing.T) {
	const token = "aBcDeF-SECRET-TOKEN"

	cases := []struct {
		name string
		in   string
		// must not appear in the output
		leaks []string
		// must appear, so the message stays diagnosable
		keeps []string
	}{
		{
			name:  "the shape net/http actually produces",
			in:    `discord: send: Post "https://discord.com/api/webhooks/123456/` + token + `": dial tcp: i/o timeout`,
			leaks: []string{token, "123456"},
			keeps: []string{"discord", "dial tcp: i/o timeout", "discord.com", URLRedacted},
		},
		{
			name:  "a query string carries secrets too",
			in:    `Post "https://hooks.example.com/x?token=` + token + `": EOF`,
			leaks: []string{token},
			keeps: []string{"hooks.example.com", "EOF"},
		},
		{
			name:  "userinfo is dropped with the rest",
			in:    `Get "https://user:` + token + `@host.example.com/p": timeout`,
			leaks: []string{token},
			keeps: []string{"host.example.com"},
		},
		{
			name:  "two URLs in one message",
			in:    `redirect https://a.example.com/` + token + ` -> https://b.example.com/` + token,
			leaks: []string{token},
			keeps: []string{"a.example.com", "b.example.com"},
		},
		{
			name:  "no URL is returned untouched",
			in:    "context deadline exceeded",
			leaks: nil,
			keeps: []string{"context deadline exceeded"},
		},
		{
			name:  "an empty message stays empty",
			in:    "",
			leaks: nil,
			keeps: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactURLsInText(tc.in)
			for _, leak := range tc.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("output still carries %q:\n  in:  %s\n  out: %s", leak, tc.in, got)
				}
			}
			for _, keep := range tc.keeps {
				if !strings.Contains(got, keep) {
					t.Errorf("output lost %q, which the operator needs:\n  in:  %s\n  out: %s",
						keep, tc.in, got)
				}
			}
		})
	}
}

// The trailing punctuation belongs to the sentence, not the URL. Go's
// error strings put a colon right after the quoted URL, and swallowing
// it would make the message read as though the host were part of the
// next clause.
func TestRedactURLsInText_KeepsSentencePunctuation(t *testing.T) {
	got := RedactURLsInText(`Post "https://h.example.com/secret": dial tcp`)
	if !strings.Contains(got, `": dial tcp`) {
		t.Errorf("the colon and the rest of the sentence must survive: %s", got)
	}
}

// Idempotent: a row redacted at persistence time is redacted again on
// the read path, and the second pass must not mangle it.
func TestRedactURLsInText_IsIdempotent(t *testing.T) {
	once := RedactURLsInText(`Post "https://discord.com/api/webhooks/1/s": EOF`)
	twice := RedactURLsInText(once)
	if once != twice {
		t.Errorf("not idempotent:\n  once:  %s\n  twice: %s", once, twice)
	}
}
