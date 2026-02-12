import { AppLayout } from './layouts/AppLayout'
import { ThemeProvider } from './providers/ThemeProvider'
import { Dashboard } from './pages/Dashboard'

function App() {
  return (
    <ThemeProvider>
      <AppLayout>
        <Dashboard />
      </AppLayout>
    </ThemeProvider>
  )
}

export default App
