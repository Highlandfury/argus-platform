import AlertIndicator from "./AlertIndicator";
import GlobalSearch from "./GlobalSearch";
import UserMenu from "./UserMenu";

export interface TopbarProps {
  email: string;
  role: string;
  orgName: string;
  onMenuToggle: () => void;
}

// Topbar is the persistent global chrome: product identity (brand lives in the
// sidebar on desktop, the mark is reachable from the collapse control), global
// search, live alert indicator, organization, help and the user menu.
export default function Topbar({
  email,
  role,
  orgName,
  onMenuToggle,
}: TopbarProps) {
  return (
    <header className="topbar" data-testid="topbar">
      <button
        type="button"
        className="topbar-menu-toggle"
        aria-label="Toggle navigation"
        onClick={onMenuToggle}
        data-testid="nav-toggle"
      >
        ☰
      </button>
      <GlobalSearch />
      <span className="topbar-spacer" />
      <div className="topbar-end">
        <AlertIndicator />
        <a
          className="topbar-icon"
          href="https://github.com/Highlandfury/argus-platform#readme"
          target="_blank"
          rel="noreferrer"
          title="Help — deployment docs live in the repository (docs/)"
          data-testid="help-link"
        >
          ?
        </a>
        <span className="topbar-sep" aria-hidden="true" />
        <span className="topbar-org" data-testid="org-name" title={orgName}>
          {orgName}
        </span>
        <UserMenu email={email} role={role} orgName={orgName} />
      </div>
    </header>
  );
}
