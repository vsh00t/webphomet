import { Outlet, Link, useLocation } from 'react-router-dom';
import { useWebSocket } from '../hooks/useWebSocket';

const NAV = [
  { path: '/', label: 'Dashboard', icon: '◉' },
];

export default function Layout() {
  const loc = useLocation();
  const { connected } = useWebSocket();

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 flex flex-col"
             style={{ background: 'var(--bg-secondary)', borderRight: '1px solid var(--border)' }}>
        <div className="p-4 text-center" style={{ borderBottom: '1px solid var(--border)' }}>
          <h1 className="text-lg font-bold" style={{ color: 'var(--accent)' }}>
            ⚡ WebPhomet
          </h1>
          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
            Autonomous Pentesting
          </p>
        </div>

        <nav className="flex-1 p-2 space-y-1">
          {NAV.map((n) => (
            <Link
              key={n.path}
              to={n.path}
              className={`block px-3 py-2 rounded text-sm transition-colors ${
                loc.pathname === n.path ? 'font-bold' : ''
              }`}
              style={{
                background: loc.pathname === n.path ? 'var(--bg-card)' : 'transparent',
                color: loc.pathname === n.path ? 'var(--accent)' : 'var(--text-secondary)',
              }}
            >
              {n.icon} {n.label}
            </Link>
          ))}
        </nav>

        <div className="p-3 text-xs" style={{ borderTop: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
          <span className={`inline-block w-2 h-2 rounded-full mr-1 ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          WS {connected ? 'connected' : 'disconnected'}
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
