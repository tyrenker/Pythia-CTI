import { useState } from 'react'
import { ExternalLink, Newspaper } from 'lucide-react'
import { useFeedArticles, useFeedSources, useTriggerFetch } from '@/api/intel-feed'
import { formatDate, timeAgo } from '@/lib/utils'
import type { FeedArticle } from '@/types/api'

function ArticleCard({ article }: { article: FeedArticle }) {
  return (
    <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface px-5 py-4 transition-colors hover:border-[#3a3a5e]">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <a
            href={article.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-medium text-[#00ff88] hover:underline"
          >
            {article.title ?? article.url}
          </a>
          {article.summary && (
            <p className="mt-1 line-clamp-2 text-xs text-text-muted">{article.summary}</p>
          )}
        </div>
        <ExternalLink size={12} className="mt-0.5 shrink-0 text-text-muted" />
      </div>
      <div className="mt-2 flex items-center gap-3 text-xs text-text-muted">
        <span className="rounded-full bg-[#1e1e2f] px-2 py-0.5">{article.source_name}</span>
        {article.published_at && (
          <span title={timeAgo(article.published_at)}>
            {formatDate(article.published_at)}
          </span>
        )}
      </div>
    </div>
  )
}

export function RecentArticles() {
  const [sourceFilter, setSourceFilter] = useState('')
  const { data: sources } = useFeedSources()
  const { data: articles, isLoading } = useFeedArticles({
    source_id: sourceFilter || undefined,
    limit: 100,
  })
  const trigger = useTriggerFetch()

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Newspaper size={16} className="text-[#00ff88]" />
          <h1 className="text-lg font-semibold text-text-primary">Recent Blogs &amp; Articles</h1>
        </div>
        <select
          value={sourceFilter}
          onChange={e => setSourceFilter(e.target.value)}
          className="border border-[#2a2a3a] bg-[#12121a] px-3 py-1.5 font-mono text-[10px] text-[#9ca3af] focus:outline-none focus:border-[#00ff88] transition-colors"
        >
          <option value="">All sources</option>
          {(sources ?? []).map(s => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
        <button
          onClick={() => trigger.mutate(undefined)}
          disabled={trigger.isPending}
          className="ml-auto bg-[#00ff88] px-4 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[#0a0a0f] cyber-chamfer-sm transition-all hover:shadow-[0_0_12px_rgba(0,255,136,0.4)] disabled:opacity-50"
        >
          {trigger.isPending ? 'PULLING…' : 'PULL_FEEDS_NOW'}
        </button>
      </div>

      {trigger.data && (
        <div className="border border-[#00ff88]/40 bg-[#00ff88]/5 px-3 py-2 font-mono text-[10px] text-[#00ff88]">
          {'> '} PULL_COMPLETE — {trigger.data.new_articles} new articles queued.
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-xs text-text-muted">
          Loading articles…
        </div>
      ) : !articles?.length ? (
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-10 text-center">
          <Newspaper size={24} className="mx-auto mb-3 text-text-muted opacity-40" />
          <p className="text-sm font-medium text-text-primary">No articles yet</p>
          <p className="mt-1 text-xs text-text-muted">
            Pull feeds from the Intel Feed page to populate recent articles.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {articles.map(a => (
            <ArticleCard key={a.id} article={a} />
          ))}
        </div>
      )}
    </div>
  )
}
