//go:build linux

/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ipset

import (
	"context"
	"strings"

	"github.com/IrineSistiana/mosdns/v4/coremain"
	"github.com/IrineSistiana/mosdns/v4/pkg/executable_seq"
	"github.com/IrineSistiana/mosdns/v4/pkg/query_context"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var _ coremain.ExecutablePlugin = (*ipsetPlugin)(nil)

type ipsetPlugin struct {
	*coremain.BP
	args   *Args
	handle *netlink.Handle
}

func newIpsetPlugin(bp *coremain.BP, args *Args) (*ipsetPlugin, error) {
	if args.Mask4 == 0 {
		args.Mask4 = 24
	}
	if args.Mask6 == 0 {
		args.Mask6 = 32
	}

	// Explicitly initialize with ONLY NETLINK_NETFILTER to avoid
	// "protocol not supported" errors on restricted environments.
	h, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}

	return &ipsetPlugin{
		BP:     bp,
		args:   args,
		handle: h,
	}, nil
}

func (p *ipsetPlugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	r := qCtx.R()
	if r != nil {
		er := p.addIPSet(r)
		if er != nil {
			p.L().Warn("failed to add response IP to ipset", qCtx.InfoField(), zap.Error(er))
		}
	}

	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *ipsetPlugin) Close() error {
	p.handle.Close()
	return nil
}

func (p *ipsetPlugin) addIPSet(r *dns.Msg) error {
	if len(r.Question) == 0 {
		return nil
	}

	comment := "DNS: " + strings.TrimSuffix(r.Question[0].Name, ".")

	for i := range r.Answer {
		switch rr := r.Answer[i].(type) {
		case *dns.A:
			if len(p.args.SetName4) == 0 {
				continue
			}
			entry := &netlink.IPSetEntry{
				IP:      rr.A,
				CIDR:    uint8(p.args.Mask4),
				Comment: comment,
				Replace: true,
			}
			if err := p.handle.IpsetAdd(p.args.SetName4, entry); err != nil {
				return err
			}

		case *dns.AAAA:
			if len(p.args.SetName6) == 0 {
				continue
			}
			entry := &netlink.IPSetEntry{
				IP:      rr.AAAA,
				CIDR:    uint8(p.args.Mask6),
				Comment: comment,
				Replace: true,
			}
			if err := p.handle.IpsetAdd(p.args.SetName6, entry); err != nil {
				return err
			}
		default:
			continue
		}
	}

	return nil
}
