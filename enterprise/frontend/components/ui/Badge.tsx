import clsx from "clsx";

const styles: Record<string, string> = {
  CRITICAL: "bg-purple-500/20 text-purple-300 border-purple-500/30",
  HIGH:     "bg-red-500/20    text-red-300    border-red-500/30",
  MEDIUM:   "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  LOW:      "bg-blue-500/20   text-blue-300   border-blue-500/30",
  SAFE:     "bg-green-500/20  text-green-300  border-green-500/30",
};

export function RiskBadge({ level }: { level: string }) {
  return (
    <span className={clsx("text-xs font-medium px-2 py-0.5 rounded-full border", styles[level] ?? styles.SAFE)}>
      {level}
    </span>
  );
}

export function BlockedBadge({ blocked }: { blocked: boolean }) {
  return blocked ? (
    <span className="text-xs font-medium px-2 py-0.5 rounded-full border bg-red-500/20 text-red-300 border-red-500/30">BLOCKED</span>
  ) : (
    <span className="text-xs font-medium px-2 py-0.5 rounded-full border bg-green-500/20 text-green-300 border-green-500/30">ALLOWED</span>
  );
}
