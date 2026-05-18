"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ShieldCheck, LayoutDashboard, AlertTriangle, ScrollText, FileText, Users, Settings, LogOut } from "lucide-react";
import clsx from "clsx";

const nav = [
  { href: "/dashboard",   label: "Dashboard",  icon: LayoutDashboard },
  { href: "/incidents",   label: "Incidents",  icon: AlertTriangle },
  { href: "/audit-logs",  label: "Audit Logs", icon: ScrollText },
  { href: "/policies",    label: "Policies",   icon: FileText },
  { href: "/developers",  label: "Developers", icon: Users },
  { href: "/settings",    label: "Settings",   icon: Settings },
];

export default function Sidebar() {
  const path = usePathname();
  const router = useRouter();

  function logout() {
    localStorage.removeItem("token");
    router.push("/login");
  }

  return (
    <aside className="w-60 shrink-0 flex flex-col bg-gray-900 border-r border-gray-800 h-screen sticky top-0">
      <div className="flex items-center gap-2.5 px-6 py-5 border-b border-gray-800">
        <ShieldCheck className="text-indigo-400" size={22} />
        <span className="font-bold text-white text-sm">Claude Safe</span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={clsx(
              "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
              path === href
                ? "bg-indigo-600/20 text-indigo-300"
                : "text-gray-400 hover:text-white hover:bg-gray-800"
            )}
          >
            <Icon size={16} />
            {label}
          </Link>
        ))}
      </nav>

      <div className="px-3 py-4 border-t border-gray-800">
        <button
          onClick={logout}
          className="flex items-center gap-3 px-3 py-2 w-full rounded-lg text-sm text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
        >
          <LogOut size={16} />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
