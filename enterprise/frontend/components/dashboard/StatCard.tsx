import { LucideIcon } from "lucide-react";
import clsx from "clsx";

interface Props {
  title: string;
  value: string | number;
  sub?: string;
  icon: LucideIcon;
  color?: "indigo" | "red" | "yellow" | "green";
}

const colors = {
  indigo: "bg-indigo-500/10 text-indigo-400",
  red:    "bg-red-500/10    text-red-400",
  yellow: "bg-yellow-500/10 text-yellow-400",
  green:  "bg-green-500/10  text-green-400",
};

export default function StatCard({ title, value, sub, icon: Icon, color = "indigo" }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-start justify-between mb-4">
        <p className="text-sm text-gray-400">{title}</p>
        <div className={clsx("p-2 rounded-lg", colors[color])}>
          <Icon size={18} />
        </div>
      </div>
      <p className="text-3xl font-bold text-white">{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  );
}
