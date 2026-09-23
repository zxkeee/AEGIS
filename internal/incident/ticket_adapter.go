package incident

import (
	"context"

	"api-gateway/internal/ticket"
)

// TicketRegister adapts the PostgreSQL store to the interface the ticket worker
// needs.
//
// The adapter lives here rather than in internal/ticket because the direction
// of the dependency matters: internal/ticket knows nothing about the register's
// schema, which is what lets it be tested with a fake and no database. The cost
// is this file; the benefit is that a change to the incidents table cannot
// break the tracker client.
type TicketRegister struct{ Store *PGStore }

// Unticketed lists incidents that should be filed and are not.
func (r TicketRegister) Unticketed(ctx context.Context, tenant, minSeverity string, limit int) ([]ticket.Incident, error) {
	rows, err := r.Store.Unticketed(ctx, tenant, Severity(minSeverity), limit)
	if err != nil {
		return nil, err
	}
	out := make([]ticket.Incident, 0, len(rows))
	for _, f := range rows {
		out = append(out, ticket.Incident{
			ID: f.ID, Title: f.Title, Class: f.Class, Subject: f.Subject,
			Severity: string(f.Severity), Detected: f.Detected, Events: f.Events,
		})
	}
	return out, nil
}

// RecordTicket stores the reference, translating "already there" into the
// sentinel the worker compares against.
//
// The translation is the point of this method existing at all: the worker has
// to tell a lost race from a storage failure, because one means "somebody else
// filed it and this ticket is a duplicate somebody must close" and the other
// means "try again next sweep".
func (r TicketRegister) RecordTicket(ctx context.Context, tenant, incidentID, system, ref, url string) error {
	err := r.Store.RecordTicket(ctx, tenant, incidentID, system, ref, url)
	if err == ErrTicketExists {
		return ticket.ErrAlreadyRecorded
	}
	return err
}

// Tenants lists the tenants with incidents.
func (r TicketRegister) Tenants(ctx context.Context) ([]string, error) {
	return r.Store.TenantsWithIncidents(ctx)
}
