// GitHub service for basic repository metadata

class GitHubService {
  constructor() {
    this.cache = new Map();
  }

  normalizeRepoUrl(repoUrl) {
    // Handle forms like:
    // - https://github.com/owner/repo
    // - https://github.com/owner/repo.git
    // - git://github.com/owner/repo.git
    // - scm:git:git://github.com/owner/repo.git
    try {
      const m = String(repoUrl).match(/github\.com\/(?:#!\/)?([^\/]+)\/([^\/#\.]+)(?:\.git)?/i);
      if (m) return { owner: m[1], repo: m[2] };
    } catch {}
    return null;
  }

  async fetchGitHubData(repoUrl) {
    if (!repoUrl) return null;
    const norm = this.normalizeRepoUrl(repoUrl);
    if (!norm) return null;
    const { owner, repo } = norm;
    const token = process.env?.REACT_APP_GITHUB_TOKEN;
    // If no token configured, skip GitHub entirely to avoid 401/429 noise
    if (!token) return null;
    const key = `github:${owner}/${repo}`;
    if (this.cache.has(key)) return this.cache.get(key);
    try {
      const headers = { Authorization: `Bearer ${token}` };

      let res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
      if (res.status === 403 || res.status === 429) {
        // Backoff once to avoid spamming and rate limits
        await new Promise((r) => setTimeout(r, 1200));
        res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
      }
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.json();
      const result = {
        releaseDate: this.formatDate(data?.created_at),
        lastUpdated: this.formatDate(data?.updated_at),
        stars: data?.stargazers_count || 0,
        forks: data?.forks_count || 0,
        license: data?.license?.name || null,
        description: data?.description || null,
        homepage: data?.homepage || null,
      };
      this.cache.set(key, result);
      return result;
    } catch {
      return null;
    }
  }

  formatDate(dateString) {
    if (!dateString) return null;
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return null;
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = d.getFullYear();
    return `${dd}-${mm}-${yyyy}`;
  }
}

export default GitHubService;


