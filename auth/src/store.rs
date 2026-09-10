// ReBAC store: who may access which repository, backed by SQLite.
//
// Lore's data path (clone/push) authorizes purely from the `resources` claim in
// the token we mint, and its privileged operations (obliterate, admin, migrate)
// read named permission strings from that same claim. So this store's job is to
// answer, per (subject, repository): is there access at all, and at what role.
// The exchange turns that answer into the `resources` claim; CreateResource
// records the creator as owner; CheckUserPermission / LookupUserPermissions read
// it back for loreserver's repository metadata and listing.
//
// Read-vs-write is deliberately NOT modeled: Lore's storage authorizes on the
// resource id alone (no per-action check on the data path), so any access grants
// both clone and push. The two roles are `owner` (access + privileged
// permissions) and `member` (access).
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use rusqlite::params;
use rusqlite::Connection;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS resources (
    urc_id     TEXT PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    subject TEXT NOT NULL,   -- a user id, or 'group:{name}'
    urc_id  TEXT NOT NULL,
    role    TEXT NOT NULL,   -- 'owner' | 'member'
    PRIMARY KEY (subject, urc_id)
);
CREATE TABLE IF NOT EXISTS group_members (
    grp     TEXT NOT NULL,
    subject TEXT NOT NULL,
    PRIMARY KEY (grp, subject)
);
";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    // Ordering matters: `Owner > Member`, so the strongest grant wins when a
    // subject reaches a resource by more than one path.
    Member,
    Owner,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }

    /// Parse a role name. `writer` is accepted as an alias for `member` (Lore has
    /// no enforceable read/write split, so there is one access role).
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "owner" => Some(Role::Owner),
            "member" | "writer" | "reader" => Some(Role::Member),
            _ => None,
        }
    }

    /// The permission strings to place in the minted token's `resources` claim.
    /// loreserver checks `owner`/`admin`/`obliterate`/`migrate` for privileged
    /// operations; `read`/`write` are informational (the data path ignores them).
    pub fn permissions(self) -> Vec<String> {
        let p: &[&str] = match self {
            Role::Owner => &["owner", "admin", "obliterate", "migrate", "read", "write"],
            Role::Member => &["read", "write"],
        };
        p.iter().map(|s| s.to_string()).collect()
    }
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> rusqlite::Result<Store> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Record a resource and make `owner` its owner. The owner grant is written
    /// only when the resource is newly created, so re-creating an existing
    /// resource (by anyone) neither changes nor adds an owner.
    pub fn record_owner(&self, owner: &str, urc_id: &str, name: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let created = conn.execute(
            "INSERT OR IGNORE INTO resources(urc_id, name, created_at) VALUES (?, ?, ?)",
            params![urc_id, name, now()],
        )?;
        if created > 0 {
            conn.execute(
                "INSERT OR IGNORE INTO grants(subject, urc_id, role) VALUES (?, ?, 'owner')",
                params![owner, urc_id],
            )?;
        }
        Ok(())
    }

    pub fn delete_resource(&self, urc_id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM grants WHERE urc_id = ?", params![urc_id])?;
        conn.execute("DELETE FROM resources WHERE urc_id = ?", params![urc_id])?;
        Ok(())
    }

    /// The subject's effective role on a resource: the strongest of its direct
    /// grant and any grant held by a group it belongs to. `None` = no access.
    pub fn role_for(&self, subject: &str, urc_id: &str) -> Option<Role> {
        let conn = self.conn.lock().unwrap();
        let mut best: Option<Role> = None;
        let mut stmt = conn
            .prepare(
                "SELECT role FROM grants WHERE urc_id = ?1 AND (
                     subject = ?2
                     OR subject IN (SELECT 'group:' || grp FROM group_members WHERE subject = ?2)
                 )",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![urc_id, subject], |r| r.get::<_, String>(0))
            .unwrap();
        for role in rows.flatten() {
            if let Some(role) = Role::parse(&role) {
                best = Some(best.map_or(role, |b| b.max(role)));
            }
        }
        best
    }

    /// Every resource the subject can reach, directly or through a group.
    pub fn accessible(&self, subject: &str) -> Vec<String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT urc_id FROM grants WHERE
                     subject = ?1
                     OR subject IN (SELECT 'group:' || grp FROM group_members WHERE subject = ?1)",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![subject], |r| r.get::<_, String>(0))
            .unwrap();
        rows.flatten().collect()
    }

    pub fn grant(&self, subject: &str, urc_id: &str, role: Role) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO grants(subject, urc_id, role) VALUES (?, ?, ?)",
            params![subject, urc_id, role.as_str()],
        )?;
        Ok(())
    }

    pub fn revoke(&self, subject: &str, urc_id: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM grants WHERE subject = ? AND urc_id = ?",
            params![subject, urc_id],
        )
    }

    pub fn add_group_member(&self, grp: &str, subject: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO group_members(grp, subject) VALUES (?, ?)",
            params![grp, subject],
        )?;
        Ok(())
    }

    pub fn remove_group_member(&self, grp: &str, subject: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM group_members WHERE grp = ? AND subject = ?",
            params![grp, subject],
        )
    }

    /// All (subject, role) grants on a resource, for the admin `ls` view.
    pub fn list_grants(&self, urc_id: &str) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT subject, role FROM grants WHERE urc_id = ? ORDER BY subject")
            .unwrap();
        let rows = stmt
            .query_map(params![urc_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap();
        rows.flatten().collect()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "urc-0194b726b34e72b0b45550b88a967076";
    const OTHER: &str = "urc-0192ae48ccf17060bc1ba9d04f6acb2f";

    #[test]
    fn creator_becomes_owner_and_re_create_keeps_first_owner() {
        let s = Store::open_in_memory().unwrap();
        s.record_owner("alice", REPO, "test").unwrap();
        assert_eq!(s.role_for("alice", REPO), Some(Role::Owner));
        // A second create by someone else does not steal ownership.
        s.record_owner("mallory", REPO, "test").unwrap();
        assert_eq!(s.role_for("alice", REPO), Some(Role::Owner));
        assert_eq!(s.role_for("mallory", REPO), None);
    }

    #[test]
    fn no_grant_means_no_access() {
        let s = Store::open_in_memory().unwrap();
        s.record_owner("alice", REPO, "").unwrap();
        assert_eq!(s.role_for("bob", REPO), None);
        assert_eq!(s.role_for("alice", OTHER), None);
    }

    #[test]
    fn direct_member_grant_gives_access_but_not_ownership() {
        let s = Store::open_in_memory().unwrap();
        s.grant("bob", REPO, Role::Member).unwrap();
        assert_eq!(s.role_for("bob", REPO), Some(Role::Member));
        assert!(!Role::Member.permissions().contains(&"owner".to_string()));
    }

    #[test]
    fn group_membership_confers_the_group_grant() {
        let s = Store::open_in_memory().unwrap();
        s.grant("group:eng", REPO, Role::Member).unwrap();
        s.add_group_member("eng", "carol").unwrap();
        assert_eq!(s.role_for("carol", REPO), Some(Role::Member));
        // Removing carol from the group revokes her access.
        s.remove_group_member("eng", "carol").unwrap();
        assert_eq!(s.role_for("carol", REPO), None);
    }

    #[test]
    fn strongest_role_wins_across_paths() {
        let s = Store::open_in_memory().unwrap();
        s.grant("dave", REPO, Role::Member).unwrap();
        s.grant("group:admins", REPO, Role::Owner).unwrap();
        s.add_group_member("admins", "dave").unwrap();
        assert_eq!(s.role_for("dave", REPO), Some(Role::Owner));
    }

    #[test]
    fn accessible_lists_direct_and_group_resources() {
        let s = Store::open_in_memory().unwrap();
        s.record_owner("erin", REPO, "").unwrap();
        s.grant("group:eng", OTHER, Role::Member).unwrap();
        s.add_group_member("eng", "erin").unwrap();
        let mut got = s.accessible("erin");
        got.sort();
        let mut want = vec![REPO.to_string(), OTHER.to_string()];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn revoke_and_delete_remove_access() {
        let s = Store::open_in_memory().unwrap();
        s.record_owner("alice", REPO, "").unwrap();
        s.grant("bob", REPO, Role::Member).unwrap();
        assert_eq!(s.revoke("bob", REPO).unwrap(), 1);
        assert_eq!(s.role_for("bob", REPO), None);
        s.delete_resource(REPO).unwrap();
        assert_eq!(s.role_for("alice", REPO), None);
        assert!(s.accessible("alice").is_empty());
    }

    #[test]
    fn owner_permissions_carry_privileged_actions() {
        let owner = Role::Owner.permissions();
        for action in ["owner", "admin", "obliterate", "migrate"] {
            assert!(owner.contains(&action.to_string()), "owner needs {action}");
        }
    }
}
