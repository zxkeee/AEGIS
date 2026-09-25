import Nav from './components/Nav.jsx'
import Hero from './components/Hero.jsx'
import TerminalSplit from './components/TerminalSplit.jsx'
import WorkflowGrid from './components/WorkflowGrid.jsx'
import Architecture from './components/Architecture.jsx'
import Deployment from './components/Deployment.jsx'
import Compliance from './components/Compliance.jsx'
import Investors from './components/Investors.jsx'
import Status from './components/Status.jsx'
import Pilot from './components/Pilot.jsx'
import Footer from './components/Footer.jsx'
import { useT } from './lib/i18n.jsx'

export default function App() {
  const t = useT()
  return (
    <div className="min-h-screen bg-canvas">
      <a href="#top" className="skip-link">{t.nav.skip}</a>
      <div id="top">
        <Nav />
      </div>
      <main className="mx-auto max-w-6xl px-6">
        <Hero />
        <TerminalSplit />
        <WorkflowGrid />
        <Architecture />
        <Deployment />
        <Compliance />
        <Investors />
        <Status />
        <Pilot />
      </main>
      <Footer />
    </div>
  )
}
