package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"slices"
)

func verifyRRSETs(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error) {

	answerSignatures, err := authenticate(r.zone.Name(), r.msg.Answer, keys, answerSection)
	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	authoritySignatures, err := authenticate(r.zone.Name(), r.msg.Ns, keys, authoritySection)
	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	recordSignatures := slices.Concat(answerSignatures, authoritySignatures)

	if err = recordSignatures.Verify(); err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	r.answer = answerSignatures
	r.authority = authoritySignatures

	return Unknown, nil
}
