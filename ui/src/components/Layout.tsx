import { NavLink, Outlet } from 'react-router-dom'
import {
  LayoutDashboard,
  Package,
  Container,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  FolderTree,
  FileText,
  Bug,
} from 'lucide-react'
import UserMenu from './UserMenu'
import SidebarBadge from './vuln/SidebarBadge'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, badge: false },
  { to: '/artifacts', label: 'Artifacts', icon: Package, badge: false },
  { to: '/projects', label: 'Projects', icon: FolderTree, badge: false },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug, badge: true },
  { to: '/license-policy', label: 'License Policy', icon: FileText, badge: false },
  { to: '/docker', label: 'Docker', icon: Container, badge: false },
  { to: '/overrides', label: 'Overrides', icon: ShieldAlert, badge: false },
  { to: '/audit-log', label: 'Audit Log', icon: ScrollText, badge: false },
  { to: '/settings', label: 'Settings', icon: Settings, badge: false },
]

export default function Layout() {
  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-60 bg-gray-900 text-white flex flex-col">
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-700">
          <ShieldCheck className="w-7 h-7 text-blue-400" />
          <span className="text-lg font-semibold tracking-tight">Shieldoo Gate</span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map(({ to, label, icon: Icon, badge }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
              {badge && <SidebarBadge />}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-700 text-xs text-gray-500">
          v{import.meta.env.VITE_APP_VERSION || 'dev'} &mdash; Apache 2.0
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="flex items-center justify-end px-6 py-3 bg-white border-b border-gray-200">
          <UserMenu />
        </header>

        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
