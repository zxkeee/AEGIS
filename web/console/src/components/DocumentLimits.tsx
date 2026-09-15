import { Info } from "@phosphor-icons/react";

// DocumentLimits renders the `limits` array every signable document carries.
//
// One component for every such document on purpose. The gateway refuses to sign
// a document that does not state what it fails to establish; showing those
// statements in two different shapes, or in only one of the places, would undo
// that at the last step — the screen is where most readers meet the document,
// and the ones who never open the JSON are exactly the ones who will quote it.
//
// Collapsed by default, expandable, never behind a link to another page: one
// click away, not one repository away.
export function DocumentLimits({
  limits,
  label = "What this does and does not prove",
  className = "",
}: {
  limits?: string[];
  label?: string;
  className?: string;
}) {
  if (!limits || limits.length === 0) return null;

  return (
    <details className={`mt-2 ${className}`}>
      <summary className="cursor-pointer text-xs text-muted hover:text-fg">
        <Info size={13} className="mr-1 inline align-[-2px]" />
        {label}
      </summary>
      <ul className="mt-1.5 space-y-1 pl-4 text-xs text-muted">
        {limits.map((l, i) => (
          <li key={i} className="list-disc">
            {l}
          </li>
        ))}
      </ul>
    </details>
  );
}
