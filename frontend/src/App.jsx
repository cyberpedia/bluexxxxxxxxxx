import { AppLayout } from './layouts/AppLayout'
import { ChallengeAdmin } from './pages/ChallengeAdmin'
import { ThemeProvider } from './providers/ThemeProvider'
import { ThemeProvider } from './providers/ThemeProvider'
import { Dashboard } from './pages/Dashboard'

function App() {
  return (
    <ThemeProvider>
      <AppLayout>
        <ChallengeAdmin />
        <Dashboard />
      </AppLayout>
    </ThemeProvider>
  )
}

export default App
