package discovery

import (
	"context"
	"database/sql"
	"strings"
)

// retemplateEndpoints rewrites catalog rows that were stored before a path
// position was learned to hold identifiers, merging them into the template that
// position now produces.
//
// The learner needs traffic before it can rule on a position, and everything
// observed during that warm-up has already been written as concrete paths. Left
// alone, those rows never change: templates become correct for future requests
// while the console keeps showing the per-object mess the learner exists to
// remove. On the assessment traffic that meant 500 catalog rows where about a
// dozen endpoints existed — the visible numbers barely moved, because the fix
// only applied to what came after it.
//
// Merging rather than deleting keeps the counters honest. Those requests really
// happened; discarding them would understate an endpoint's traffic, and traffic
// is what posture and the findings' "N requests arrived without authentication"
// are computed from.
//
// prefix is the template up to (not including) the collapsed position, so a
// prefix of "/api/v1/repos" turns "/api/v1/repos/forgejo/x" into
// "/api/v1/repos/{id}/x". Rows already carrying the placeholder there are
// skipped, which makes the operation idempotent and safe to repeat.
func (s *pgStore) retemplateEndpoints(ctx context.Context, tenantID, prefix string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		groups, templates, err := supersededGroups(ctx, tx, tenantID, prefix)
		if err != nil {
			return err
		}
		for newID, oldIDs := range groups {
			if err := mergeEndpointGroup(ctx, tx, tenantID, newID, templates[newID], oldIDs); err != nil {
				return err
			}
		}
		return nil
	})
}

// supersededGroups finds the stored rows sitting under prefix whose next segment
// is still concrete, and groups their ids by the endpoint id they now belong to.
func supersededGroups(ctx context.Context, tx *sql.Tx, tenantID, prefix string) (
	groups map[string][]string, templates map[string]string, err error) {

	rs, err := tx.QueryContext(ctx,
		`SELECT id, method, path_template FROM api_endpoints
		  WHERE tenant_id = $1 AND path_template LIKE $2`,
		tenantID, prefix+"/%")
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if cerr := rs.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	groups = map[string][]string{}
	templates = map[string]string{}
	for rs.Next() {
		var id, method, tmpl string
		if err := rs.Scan(&id, &method, &tmpl); err != nil {
			return nil, nil, err
		}
		newTmpl, changed := retemplatePath(prefix, tmpl)
		if !changed {
			continue
		}
		newID := strings.ToUpper(method) + " " + newTmpl
		groups[newID] = append(groups[newID], id)
		templates[newID] = newTmpl
	}
	if err := rs.Err(); err != nil {
		return nil, nil, err
	}
	return groups, templates, nil
}

// mergeEndpointGroup folds every row in oldIDs into newID across the three
// tables keyed by an endpoint id, then removes the originals.
//
// The aggregation happens in SQL rather than row by row because several old
// rows collapse onto the same new id: inserted one at a time, each ON CONFLICT
// would be fighting the insert before it.
func mergeEndpointGroup(ctx context.Context, tx *sql.Tx, tenantID, newID, newTemplate string, oldIDs []string) error {
	// posture and risk_score are classifications, not counters, so they are not
	// summed. The worst posture and the highest risk among the merged rows win:
	// an endpoint that was unprotected for some of its objects is unprotected.
	// The ordering is spelled out rather than relying on the text sort, which
	// only lines up with severity by coincidence.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_endpoints (
			tenant_id, id, method, path_template, first_seen, last_seen,
			request_count, error_count, auth_present_count, anon_count,
			pii_count, pii_types, latency_ms_sum, latency_samples,
			posture, risk_score, route_path)
		SELECT $1, $2, MIN(method), $3,
		       MIN(first_seen), MAX(last_seen),
		       SUM(request_count), SUM(error_count), SUM(auth_present_count),
		       SUM(anon_count), SUM(pii_count),
		       -- ARRAY_AGG over the array column cannot be used here: Postgres
		       -- refuses to accumulate empty arrays, and most rows have none.
		       COALESCE((SELECT ARRAY_AGG(DISTINCT t)
		                   FROM api_endpoints src, UNNEST(src.pii_types) AS t
		                  WHERE src.tenant_id = $1 AND src.id = ANY($4)), '{}'),
		       SUM(latency_ms_sum), SUM(latency_samples),
		       (ARRAY_AGG(posture ORDER BY 
		            CASE posture WHEN 'unprotected' THEN 0 WHEN 'shadow' THEN 1
		                 WHEN 'partial' THEN 2 ELSE 3 END))[1],
		       MAX(risk_score), MIN(route_path)
		  FROM api_endpoints
		 WHERE tenant_id = $1 AND id = ANY($4)
		ON CONFLICT (tenant_id, id) DO UPDATE SET
			first_seen         = LEAST(api_endpoints.first_seen, EXCLUDED.first_seen),
			last_seen          = GREATEST(api_endpoints.last_seen, EXCLUDED.last_seen),
			request_count      = api_endpoints.request_count + EXCLUDED.request_count,
			error_count        = api_endpoints.error_count + EXCLUDED.error_count,
			auth_present_count = api_endpoints.auth_present_count + EXCLUDED.auth_present_count,
			anon_count         = api_endpoints.anon_count + EXCLUDED.anon_count,
			pii_count          = api_endpoints.pii_count + EXCLUDED.pii_count,
			pii_types          = ARRAY(SELECT DISTINCT UNNEST(api_endpoints.pii_types || EXCLUDED.pii_types)),
			latency_ms_sum     = api_endpoints.latency_ms_sum + EXCLUDED.latency_ms_sum,
			latency_samples    = api_endpoints.latency_samples + EXCLUDED.latency_samples,
			risk_score         = GREATEST(api_endpoints.risk_score, EXCLUDED.risk_score),
			-- The worse posture wins. Omitting this let a template row that had
			-- already been written as "partial" keep that label after absorbing
			-- rows that were unprotected — the merge would have hidden the very
			-- exposure the catalog exists to surface.
			posture = CASE
				WHEN (CASE EXCLUDED.posture WHEN 'unprotected' THEN 0 WHEN 'shadow' THEN 1
				           WHEN 'partial' THEN 2 ELSE 3 END)
				   < (CASE api_endpoints.posture WHEN 'unprotected' THEN 0 WHEN 'shadow' THEN 1
				           WHEN 'partial' THEN 2 ELSE 3 END)
				THEN EXCLUDED.posture ELSE api_endpoints.posture END`,
		tenantID, newID, newTemplate, oldIDs); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_endpoint_status (tenant_id, endpoint_id, status, count)
		SELECT $1, $2, status, SUM(count)
		  FROM api_endpoint_status
		 WHERE tenant_id = $1 AND endpoint_id = ANY($3)
		 GROUP BY status
		ON CONFLICT (tenant_id, endpoint_id, status) DO UPDATE
			SET count = api_endpoint_status.count + EXCLUDED.count`,
		tenantID, newID, oldIDs); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_endpoint_consumers (tenant_id, endpoint_id, consumer_id, request_count, last_seen)
		SELECT $1, $2, consumer_id, SUM(request_count), MAX(last_seen)
		  FROM api_endpoint_consumers
		 WHERE tenant_id = $1 AND endpoint_id = ANY($3)
		 GROUP BY consumer_id
		ON CONFLICT (tenant_id, endpoint_id, consumer_id) DO UPDATE
			SET request_count = api_endpoint_consumers.request_count + EXCLUDED.request_count,
			    last_seen     = GREATEST(api_endpoint_consumers.last_seen, EXCLUDED.last_seen)`,
		tenantID, newID, oldIDs); err != nil {
		return err
	}

	// Delete last, and never the row just written: a concrete path that already
	// equalled its own template would otherwise delete the merged result.
	for _, q := range []string{
		`DELETE FROM api_endpoint_status    WHERE tenant_id = $1 AND endpoint_id = ANY($2) AND endpoint_id <> $3`,
		`DELETE FROM api_endpoint_consumers WHERE tenant_id = $1 AND endpoint_id = ANY($2) AND endpoint_id <> $3`,
		`DELETE FROM api_endpoints          WHERE tenant_id = $1 AND id = ANY($2) AND id <> $3`,
	} {
		if _, err := tx.ExecContext(ctx, q, tenantID, oldIDs, newID); err != nil {
			return err
		}
	}
	return nil
}

// retemplatePath replaces the segment immediately after prefix with the id
// placeholder. It reports false when tmpl does not sit under prefix, or already
// carries the placeholder there.
func retemplatePath(prefix, tmpl string) (string, bool) {
	if !strings.HasPrefix(tmpl, prefix+"/") {
		return tmpl, false
	}
	rest := tmpl[len(prefix)+1:]
	seg, tail, hasTail := strings.Cut(rest, "/")
	if seg == placeholder || seg == "" {
		return tmpl, false
	}
	out := prefix + "/" + placeholder
	if hasTail && tail != "" {
		out += "/" + tail
	}
	return out, true
}
