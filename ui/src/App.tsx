import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Artifacts from './pages/Artifacts'
import DockerRepositories from './pages/DockerRepositories'
import DockerRepositoryDetail from './pages/DockerRepositoryDetail'
import AuditLog from './pages/AuditLog'
import Overrides from './pages/Overrides'
import Settings from './pages/Settings'
import Profile from './pages/Profile'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/artifacts" element={<Artifacts />} />
            <Route path="/docker" element={<DockerRepositories />} />
            <Route path="/docker/repositories/:id" element={<DockerRepositoryDetail />} />
            <Route path="/overrides" element={<Overrides />} />
            <Route path="/audit-log" element={<AuditLog />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/profile" element={<Profile />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
