package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func cname(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error {
	cnames := extractRecords[*dns.CNAME](r.Msg.Answer)

	targets := make([]string, len(cnames))
	for i, c := range cnames {
		targets[i] = c.Target
	}

	Debug(fmt.Sprintf("resolved [%s]  to cnames: [%s]",
		qmsg.Question[0].Name,
		strings.Join(targets, ", ")),
	)

	for _, c := range cnames {
		target := dns.CanonicalName(c.Target)

		if recordsOfNameAndTypeExist(r.Msg.Answer, target, qmsg.Question[0].Qtype) || recordsOfNameAndTypeExist(r.Msg.Answer, target, dns.TypeCNAME) {
			// Skip over if the answer already contains a record for the target.
			continue
		}

		cnameQMsg := new(dns.Msg)
		cnameQMsg.SetQuestion(target, qmsg.Question[0].Qtype)

		if isSetDO(qmsg) {
			cnameQMsg.SetEdns0(4096, true)
		}

		cnameRMsg := exchanger.exchange(ctx, cnameQMsg)

		if cnameRMsg.HasError() {
			return cnameRMsg.Err
		}
		if cnameRMsg.IsEmpty() {
			return fmt.Errorf("unable to follow cname [%s]", c.Target)
		}

		r.Msg.Answer = append(r.Msg.Answer, cnameRMsg.Msg.Answer...)
		r.Msg.Ns = append(r.Msg.Ns, cnameRMsg.Msg.Ns...)
		r.Msg.Extra = append(r.Msg.Extra, cnameRMsg.Msg.Extra...)

		// Ensure we handle differing DNSSEC results correctly.
		r.Auth = r.Auth.Combine(cnameRMsg.Auth)

		// The overall message is only authoritative if all answers are.
		r.Msg.Authoritative = r.Msg.Authoritative && cnameRMsg.Msg.Authoritative

		// Ensures we don't return 0 if any message was not 0. TODO: should this be more sophisticated?
		r.Msg.Rcode = max(r.Msg.Rcode, cnameRMsg.Msg.Rcode)
	}

	return nil
}
