import { AppLayout } from './layouts/AppLayout'
import { ChallengeAdmin } from './pages/ChallengeAdmin'
import { ThemeProvider } from './providers/ThemeProvider'

function App() {
  return (
    <ThemeProvider>
      <AppLayout>
        <ChallengeAdmin />
      </AppLayout>
    </ThemeProvider>
  )
}

export default App
