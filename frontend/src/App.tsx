import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Shell } from './components/layout/Shell'
import { Dashboard } from './pages/Dashboard'
import { IntelFeed } from './pages/IntelFeed'
import { ThreatDetail } from './pages/ThreatDetail'
import { Actors } from './pages/Actors'
import { ActorDetail } from './pages/ActorDetail'
import { Ttps } from './pages/Ttps'
import { TtpDetail } from './pages/TtpDetail'
import { Iocs } from './pages/Iocs'
import { IocDetail } from './pages/IocDetail'
import { Rules } from './pages/Rules'
import { RuleDetail } from './pages/RuleDetail'
import { Malware } from './pages/Malware'
import { MalwareDetail } from './pages/MalwareDetail'
import { AiThreats } from './pages/AiThreats'
import { Analytics } from './pages/Analytics'
import { Watchlist } from './pages/Watchlist'
import { Docs } from './pages/Docs'
import { RecentArticles } from './pages/RecentArticles'
import { HuntList } from './pages/HuntList'
import { HuntWorkbench } from './pages/HuntWorkbench'

export default function App() {
  return (
    <BrowserRouter>
      <Shell>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/intel" element={<IntelFeed />} />
          <Route path="/intel/:id" element={<ThreatDetail />} />
          <Route path="/actors" element={<Actors />} />
          <Route path="/actors/:id" element={<ActorDetail />} />
          <Route path="/ttps" element={<Ttps />} />
          <Route path="/ttps/:id" element={<TtpDetail />} />
          <Route path="/iocs" element={<Iocs />} />
          <Route path="/iocs/:id" element={<IocDetail />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/rules/:type/:id" element={<RuleDetail />} />
          <Route path="/malware" element={<Malware />} />
          <Route path="/malware/:id" element={<MalwareDetail />} />
          <Route path="/ai-threats" element={<AiThreats />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/watchlist" element={<Watchlist />} />
          <Route path="/docs" element={<Docs />} />
          <Route path="/articles" element={<RecentArticles />} />
          <Route path="/hunt" element={<HuntList />} />
          <Route path="/hunt/:id" element={<HuntWorkbench />} />
        </Routes>
      </Shell>
    </BrowserRouter>
  )
}
