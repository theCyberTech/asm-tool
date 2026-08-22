import { useMemo, useState, type ReactNode } from "react";

export type Column<T> = {
  key: string;
  header: string;
  value: (row: T) => string | number;
  render?: (row: T) => ReactNode;
};

type DataTableProps<T> = {
  rows: T[];
  columns: Array<Column<T>>;
  emptyTitle: string;
  emptyDescription: string;
  filterPlaceholder?: string;
};

export function DataTable<T>({
  rows,
  columns,
  emptyTitle,
  emptyDescription,
  filterPlaceholder = "Filter results",
}: DataTableProps<T>) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const matched = needle
      ? rows.filter((row) =>
          columns.some((column) => String(column.value(row)).toLowerCase().includes(needle)),
        )
      : rows.slice();

    const sorted = matched.slice();
    if (!sortKey) {
      return sorted;
    }
    const column = columns.find((item) => item.key === sortKey);
    if (!column) {
      return sorted;
    }
    return sorted.sort((a, b) => {
      const left = column.value(a);
      const right = column.value(b);
      const cmp = typeof left === "number" && typeof right === "number"
        ? left - right
        : String(left).localeCompare(String(right), undefined, { numeric: true });
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [columns, query, rows, sortDir, sortKey]);

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        <h3>{emptyTitle}</h3>
        <p>{emptyDescription}</p>
      </div>
    );
  }

  function toggleSort(key: string) {
    if (sortKey === key) {
      setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setSortDir("asc");
  }

  return (
    <>
      <div className="modal-search">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={filterPlaceholder}
          aria-label={filterPlaceholder}
        />
      </div>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={`sortable${sortKey === column.key ? ` ${sortDir}` : ""}`}
                >
                  <button type="button" className="sortable" onClick={() => toggleSort(column.key)}>
                    {column.header}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row, index) => (
              <tr key={index}>
                {columns.map((column) => (
                  <td key={column.key}>{column.render ? column.render(row) : String(column.value(row))}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="row-count mt-sm">
        Showing {filtered.length} of {rows.length}
      </p>
    </>
  );
}
