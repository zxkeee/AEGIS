import Nav from './components/Nav.jsx'
import Hero from './components/Hero.jsx'
import TerminalSplit from './components/TerminalSplit.jsx'
import WorkflowGrid from './components/WorkflowGrid.jsx'
import Architecture from './components/Architecture.jsx'
import Deployment from './components/Deployment.jsx'
import Compliance from './components/Compliance.jsx'
import Status from './components/Status.jsx'
import Pilot from './components/Pilot.jsx'
import Footer from './components/Footer.jsx'

export default function App() {
  return (
    <div className="min-h-screen bg-canvas">
      <a href="#top" className="skip-link">Skip to content</a>
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
        <Status />
        <Pilot />
      </main>
      <Footer />
    </div>
  )
}
