//! Failing-first controls for the PR #59 review at fec93ac. Each test names the finding it guards
//! and fails on the code before that finding's fix. Positive controls in the same test pin the
//! behaviour the fix must keep.

use super::*;
use crate::ignore::Ignore;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};

fn scratch(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("stoop-witness-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    fs::canonicalize(&base).unwrap()
}

fn stat_of(path: &Path) -> identity::FileStat {
    identity::file_stat(&fs::symlink_metadata(path).unwrap())
}

fn landing(ino: u64, mode: u32) -> AtomicLanding {
    AtomicLanding {
        stat: identity::FileStat {
            dev: 1,
            ino,
            size: 1,
            mtime_ns: 1,
            ctime_ns: 1,
            mode,
        },
        hash: "h".into(),
    }
}

fn rec_for<'a>(root: &Path, ignore: &'a Ignore) -> Rec<'a> {
    Rec {
        phys: Physical::new(root, root),
        footprint_phys: Physical::new(root, root),
        ignore,
        root: root.to_path_buf(),
        hashed: 0,
        read_budget: ReadBudget::default(),
        rewrite_budget: ReadBudget::default(),
        prior_binding: None,
        oid_epoch: None,
        link_walks: BTreeMap::new(),
        redirected_reads: HashSet::new(),
    }
}

fn tracer_for(rec: Rec<'_>) -> Tracer<'_> {
    Tracer {
        ops: HashMap::new(),
        cwds: HashMap::new(),
        magic_epoch: 0,
        magic_cache: HashMap::new(),
        pending_topology: HashSet::new(),
        pending_witness: HashMap::new(),
        confirmed_reads: HashMap::new(),
        landing_inodes: HashMap::new(),
        shared_context: false,
        initial_pid_namespace: is_initial_pid_namespace(fs::read_link("/proc/self/ns/pid")),
        live_tasks: HashSet::new(),
        syscall: 0,
        allow_network: false,
        rec: Some(rec),
        execs: None,
        t: Trace::default(),
    }
}

/// Argument registers for a call whose path argument is `path` at index 1 and no dirfd.
fn path_args(path: &CString) -> [u64; 6] {
    let mut args = [0u64; 6];
    args[1] = path.as_ptr() as u64;
    args
}

/// Finding P2-3: withdrawing the landings under `d` must reach `d/f` even when `d.old` sorts
/// between `d` and `d/f`, and must keep `d.old`, `d0` and `e/f`, which are not descendants.
#[test]
fn descendant_landings_are_withdrawn_past_interleaved_sibling_names() {
    let root = Path::new("/repo");
    let mut trace = Trace::default();
    let mut inodes = HashMap::new();
    for (key, ino) in [("d.old", 2), ("d/f", 3), ("d0", 4), ("e/f", 5)] {
        trace
            .atomic_landings
            .insert(key.to_string(), landing(ino, 0o100644));
        inodes.insert((1, ino), key.to_string());
    }
    invalidate_landing_path(&mut trace, &mut inodes, root, &root.join("d"));
    let kept: Vec<&str> = trace.atomic_landings.keys().map(String::as_str).collect();
    assert_eq!(
        kept,
        ["d.old", "d0", "e/f"],
        "P2-3: a chmod of d must withdraw d/f past the sibling d.old"
    );
    assert!(
        !inodes.contains_key(&(1, 3)),
        "P2-3: the withdrawn inode is still mapped"
    );
}

/// Whether a prior bound to `phys` verifies when the pathname stat that chose its prefix is
/// `pathname`.
fn prior_verifies(root: &Path, phys: &Path, pathname: &fs::Metadata) -> bool {
    let ignore = Ignore::new(&[], None, &[]);
    let mut rec = rec_for(root, &ignore);
    rec.prior_binding = Some(PriorBinding {
        key: "f".into(),
        seen: Seen::File(stat_of(phys), identity::ReadHash::NotNeeded),
        verified: false,
    });
    let mut t = Trace::default();
    let _ = rec.prior_content_id(&mut t, phys, "f", pathname);
    rec.prior_binding.as_ref().unwrap().verified
}

/// Finding P2-4: the `f:`/`x:` prefix of a bound prior comes from the pathname stat, and the
/// witness must not verify when that stat disagrees with the bound descriptor, in either
/// direction. Both files hold the same bytes, so only the execute bit differs.
#[test]
fn a_bound_prior_needs_the_pathname_stat_that_chose_its_prefix() {
    let root = scratch("prior-bound");
    let f = root.join("f");
    let x = root.join("x");
    fs::write(&f, b"same\n").unwrap();
    fs::write(&x, b"same\n").unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&x, fs::Permissions::from_mode(0o755)).unwrap();
    let f_meta = fs::symlink_metadata(&f).unwrap();
    let x_meta = fs::symlink_metadata(&x).unwrap();
    assert!(
        prior_verifies(&root, &f, &f_meta),
        "control: a pathname stat that agrees with the descriptor verifies"
    );
    assert!(
        !prior_verifies(&root, &f, &x_meta),
        "P2-4: an executable pathname stat must not verify a non-executable descriptor"
    );
    assert!(
        !prior_verifies(&root, &x, &f_meta),
        "P2-4: a non-executable pathname stat must not verify an executable descriptor"
    );
    fs::remove_dir_all(root).unwrap();
}

/// Finding P2-5: a witness lookup must not fill the legacy parent cache. Here the parent is
/// redirected after the lookup. The legacy writer must name the redirected parent, as it does
/// with no witness lookup at all.
#[test]
fn a_witness_lookup_leaves_the_legacy_parent_cache_as_it_was() {
    let build = |root: &Path| {
        fs::create_dir_all(root.join("d")).unwrap();
        fs::create_dir_all(root.join("d2")).unwrap();
        fs::write(root.join("d/f"), b"x").unwrap();
        fs::write(root.join("d2/f"), b"x").unwrap();
    };
    let redirect = |root: &Path| {
        fs::rename(root.join("d"), root.join("d-moved")).unwrap();
        symlink(root.join("d2"), root.join("d")).unwrap();
    };

    let control_root = scratch("parent-cache-control");
    build(&control_root);
    let ignore = Ignore::new(&[], None, &[]);
    let mut legacy = rec_for(&control_root, &ignore);
    redirect(&control_root);
    let mut t = Trace::default();
    assert_eq!(
        legacy
            .write(&mut t, &control_root.join("d/f"), false)
            .as_deref(),
        Some("d2/f"),
        "control: the legacy writer names the redirected parent"
    );

    let witness_root = scratch("parent-cache-witness");
    build(&witness_root);
    let mut tracer = tracer_for(rec_for(&witness_root, &ignore));
    tracer.topology_changed(0);
    assert_eq!(
        tracer.exact_key(&witness_root.join("d/f")).as_deref(),
        Some("d/f"),
        "control: the witness lookup names the parent before the redirect"
    );
    redirect(&witness_root);
    let rec = tracer.rec.as_mut().unwrap();
    assert_eq!(
        rec.write(&mut tracer.t, &witness_root.join("d/f"), false)
            .as_deref(),
        Some("d2/f"),
        "P2-5: a witness lookup refilled the legacy parent cache with the stale parent"
    );
    fs::remove_dir_all(control_root).unwrap();
    fs::remove_dir_all(witness_root).unwrap();
}

/// Finding P2-2: a read witness must name only an ordinary spelling. A `/proc` route and a
/// symlink that leads into `/proc` must not produce a candidate even though the resolver maps
/// both to the ordinary file. The ordinary absolute spelling is the control.
#[test]
fn a_read_witness_names_only_an_ordinary_spelling() {
    let root = scratch("route");
    let f = root.join("f");
    fs::write(&f, b"x").unwrap();
    let ignore = Ignore::new(&[], None, &[]);
    let mut tracer = tracer_for(rec_for(&root, &ignore));
    tracer.t.seen = Some(HashMap::from([(
        f.clone(),
        identity::Observation {
            seen: Seen::File(stat_of(&f), identity::ReadHash::NotNeeded),
            route_physical: true,
            appeared: false,
        },
    )]));
    let pid = std::process::id() as i32;

    let ordinary = CString::new(f.as_os_str().as_bytes()).unwrap();
    assert!(
        tracer
            .read_candidate(pid, &path_args(&ordinary), None, 1, &f)
            .is_some(),
        "control: an ordinary absolute spelling yields a candidate"
    );

    let proc_route = CString::new("/proc/self/cwd/f").unwrap();
    assert!(
        tracer
            .read_candidate(pid, &path_args(&proc_route), None, 1, &f)
            .is_none(),
        "P2-2: a /proc route must not yield a read witness"
    );

    let fd = fs::File::open(&f).unwrap();
    let alias = root.join("alias");
    symlink(format!("/proc/self/fd/{}", fd.as_raw_fd()), &alias).unwrap();
    let alias_spelling = CString::new(alias.as_os_str().as_bytes()).unwrap();
    assert!(
        tracer
            .read_candidate(pid, &path_args(&alias_spelling), None, 1, &f)
            .is_none(),
        "P2-2: a symlink into /proc must not yield a read witness under the ordinary name"
    );
    drop(fd);

    let other = root.join("g");
    fs::write(&other, b"y").unwrap();
    let other_spelling = CString::new(other.as_os_str().as_bytes()).unwrap();
    assert!(
        tracer
            .read_candidate(pid, &path_args(&other_spelling), None, 1, &f)
            .is_none(),
        "P2-2: a call that names another file than the witness path must not yield a candidate"
    );
    fs::remove_dir_all(root).unwrap();
}

/// Whether `rename_candidate` offers a rename witness for these operands and spellings.
fn rename_offered(
    tracer: &mut Tracer<'_>,
    pid: i32,
    args: &[u64; 6],
    source: &Path,
    target: &Path,
    metas: (&fs::Metadata, &fs::Metadata),
) -> bool {
    tracer
        .rename_candidate(
            pid,
            args,
            RenameOperation {
                from: (None, 1),
                to: (None, 2),
                flags: None,
                a: source,
                b: target,
                a_meta: Some(metas.0),
                b_meta: Some(metas.1),
            },
        )
        .is_some()
}

/// Finding P2-2 on the rename side: an operand named through a `/proc` route must not yield a
/// rename witness, while the ordinary spelling of the same rename does. The source is the
/// command's own temporary file, which the rename witness requires.
#[test]
fn a_rename_witness_names_only_ordinary_operands() {
    let root = scratch("rename-route");
    let temp = root.join("t");
    let target = root.join("f");
    fs::write(&temp, b"new\n").unwrap();
    fs::write(&target, b"old\n").unwrap();
    let metas = (
        fs::symlink_metadata(&temp).unwrap(),
        fs::symlink_metadata(&target).unwrap(),
    );
    let ignore = Ignore::new(&[], None, &[]);
    let mut tracer = tracer_for(rec_for(&root, &ignore));
    tracer.initial_pid_namespace = true;
    let pid = std::process::id() as i32;
    tracer.live_tasks.insert(pid);
    tracer.t.keys.insert(temp.clone(), "t".into());
    tracer.t.priors.insert("t".into(), "a".into());
    let seen = Seen::File(stat_of(&target), identity::ReadHash::NotNeeded);
    tracer.confirmed_reads.insert(target.clone(), seen.clone());
    tracer.t.seen = Some(HashMap::from([(
        target.clone(),
        identity::Observation {
            seen,
            route_physical: true,
            appeared: false,
        },
    )]));

    let source_spelling = CString::new(temp.as_os_str().as_bytes()).unwrap();
    let target_spelling = CString::new(target.as_os_str().as_bytes()).unwrap();
    let mut args = [0u64; 6];
    args[1] = source_spelling.as_ptr() as u64;
    args[2] = target_spelling.as_ptr() as u64;
    let proc_spelling = CString::new("/proc/self/cwd/t").unwrap();
    let mut proc_args = args;
    proc_args[1] = proc_spelling.as_ptr() as u64;

    assert!(
        rename_offered(
            &mut tracer,
            pid,
            &args,
            &temp,
            &target,
            (&metas.0, &metas.1)
        ),
        "control: the ordinary spelling of the rename yields a rename witness"
    );
    assert!(
        !rename_offered(
            &mut tracer,
            pid,
            &proc_args,
            &temp,
            &target,
            (&metas.0, &metas.1)
        ),
        "P2-2: a /proc route as the rename source must not yield a rename witness"
    );
    fs::remove_dir_all(root).unwrap();
}

fn with_ordinary_rename(
    name: &str,
    check: impl FnOnce(&mut Tracer<'_>, i32, &[u64; 6], &Path, &Path, (&fs::Metadata, &fs::Metadata)),
) {
    let root = scratch(name);
    let temp = root.join("t");
    let target = root.join("f");
    fs::write(&temp, b"new\n").unwrap();
    fs::write(&target, b"old\n").unwrap();
    let metas = (
        fs::symlink_metadata(&temp).unwrap(),
        fs::symlink_metadata(&target).unwrap(),
    );
    let ignore = Ignore::new(&[], None, &[]);
    let mut tracer = tracer_for(rec_for(&root, &ignore));
    let pid = std::process::id() as i32;
    tracer.live_tasks.insert(pid);
    tracer.t.keys.insert(temp.clone(), "t".into());
    tracer.t.priors.insert("t".into(), "a".into());
    let seen = Seen::File(stat_of(&target), identity::ReadHash::NotNeeded);
    tracer.confirmed_reads.insert(target.clone(), seen.clone());
    tracer.t.seen = Some(HashMap::from([(
        target.clone(),
        identity::Observation {
            seen,
            route_physical: true,
            appeared: false,
        },
    )]));
    let source = CString::new(temp.as_os_str().as_bytes()).unwrap();
    let destination = CString::new(target.as_os_str().as_bytes()).unwrap();
    let mut args = [0u64; 6];
    args[1] = source.as_ptr() as u64;
    args[2] = destination.as_ptr() as u64;
    check(
        &mut tracer,
        pid,
        &args,
        &temp,
        &target,
        (&metas.0, &metas.1),
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_oversized_lock_table_withholds_the_witness() {
    let stat = landing(42, 0o100644).stat;
    let table = vec![b' '; (1 << 20) + 1];
    assert!(
        lock_table_lists_from(Ok(io::Cursor::new(table)), &stat),
        "an oversized lock table must fall back to the legacy recorder"
    );
}

#[test]
fn an_over_budget_source_is_not_scanned_or_opened() {
    with_ordinary_rename("budget-limit", |tracer, pid, args, temp, target, metas| {
        tracer.initial_pid_namespace = true;
        let used = identity::READ_HASH_BUDGET - 3;
        tracer.rec.as_mut().unwrap().rewrite_budget.hashed = used;
        let scans_before = LOCK_TABLE_SCANS.with(|scans| scans.get());
        assert!(!rename_offered(tracer, pid, args, temp, target, metas));
        assert_eq!(
            LOCK_TABLE_SCANS.with(|scans| scans.get()),
            scans_before,
            "an over-budget source must not scan the lock table"
        );
        assert_eq!(
            tracer.rec.as_ref().unwrap().rewrite_budget.hashed,
            used,
            "an over-budget source must not be opened or hashed"
        );
    });
}

#[test]
#[ignore = "requires a child PID namespace with its own procfs"]
fn a_child_pid_namespace_withholds_the_rename_witness() {
    let namespace = fs::read_link("/proc/self/ns/pid").expect("PID namespace");
    assert_ne!(namespace, Path::new("pid:[4026531836]"));
    with_ordinary_rename(
        "child-pid-namespace",
        |tracer, pid, args, temp, target, metas| {
            assert!(
                !rename_offered(tracer, pid, args, temp, target, metas),
                "a child PID namespace cannot establish lock-table completeness"
            );
        },
    );
}

#[test]
fn initial_pid_namespace_requires_the_kernel_initial_inode() {
    assert_eq!(PROC_PID_INIT_INO, 4_026_531_836);
    assert!(is_initial_pid_namespace(Ok(PathBuf::from(
        "pid:[4026531836]"
    ))));
    for name in [
        "pid:[4026531837]",
        "pid:[4026532194]",
        "mnt:[4026531836]",
        "pid:[4026531836]\n",
        "pid:[0xeffffffc]",
    ] {
        assert!(!is_initial_pid_namespace(Ok(PathBuf::from(name))), "{name}");
    }
    assert!(!is_initial_pid_namespace(Err(io::Error::from(
        io::ErrorKind::NotFound
    ))));
    assert!(!is_initial_pid_namespace(Err(io::Error::from(
        io::ErrorKind::PermissionDenied
    ))));
}

#[test]
fn a_cached_child_namespace_never_scans_the_lock_table() {
    with_ordinary_rename(
        "namespace-guard",
        |tracer, pid, args, temp, target, metas| {
            tracer.initial_pid_namespace = false;
            let scans = LOCK_TABLE_SCANS.with(|count| count.get());
            let used = tracer.rec.as_ref().unwrap().rewrite_budget.hashed;
            assert!(!rename_offered(tracer, pid, args, temp, target, metas));
            assert_eq!(LOCK_TABLE_SCANS.with(|count| count.get()), scans);
            assert_eq!(tracer.rec.as_ref().unwrap().rewrite_budget.hashed, used);

            tracer.initial_pid_namespace = true;
            assert!(rename_offered(tracer, pid, args, temp, target, metas));
            assert_eq!(LOCK_TABLE_SCANS.with(|count| count.get()), scans + 1);
        },
    );
}

#[test]
fn source_budget_boundary_admits_only_bytes_that_can_be_hashed() {
    with_ordinary_rename(
        "budget-boundary",
        |tracer, pid, args, temp, target, metas| {
            tracer.initial_pid_namespace = true;
            let before = identity::READ_HASH_BUDGET - 4;
            tracer.rec.as_mut().unwrap().rewrite_budget.hashed = before;
            assert!(rename_offered(tracer, pid, args, temp, target, metas));
            assert_eq!(
                tracer.rec.as_ref().unwrap().rewrite_budget.hashed,
                identity::READ_HASH_BUDGET
            );
            fs::write(temp, b"").unwrap();
            let empty = fs::symlink_metadata(temp).unwrap();
            assert!(rename_offered(
                tracer,
                pid,
                args,
                temp,
                target,
                (&empty, metas.1)
            ));
            tracer.rec.as_mut().unwrap().rewrite_budget.hashed = identity::READ_HASH_BUDGET + 1;
            let scans = LOCK_TABLE_SCANS.with(|count| count.get());
            assert!(!rename_offered(
                tracer,
                pid,
                args,
                temp,
                target,
                (&empty, metas.1)
            ));
            assert_eq!(LOCK_TABLE_SCANS.with(|count| count.get()), scans);
        },
    );
}

#[test]
fn lock_table_accepts_exact_cap_and_fails_closed_on_read_errors() {
    let stat = landing(42, 0o100644).stat;
    let exact = vec![b' '; 1 << 20];
    assert!(!lock_table_lists_from(Ok(io::Cursor::new(exact)), &stat));
    assert!(lock_table_lists_from::<io::Cursor<Vec<u8>>>(
        Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        &stat
    ));
    assert!(lock_table_lists_from(
        Ok(io::Cursor::new(vec![0xff])),
        &stat
    ));
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read error"))
        }
    }
    assert!(lock_table_lists_from(Ok(Broken), &stat));
}

#[test]
fn matching_inode_is_conservative_across_different_devices() {
    let stat = landing(42, 0o100644).stat;
    let different_device = b"1: LEASE ADVISORY WRITE 7 00:ff:42 0 EOF\n";
    assert!(lock_table_lists_from(
        Ok(io::Cursor::new(different_device)),
        &stat
    ));
    let other_inode = b"1: LEASE ADVISORY WRITE 7 00:ff:43 0 EOF\n";
    assert!(!lock_table_lists_from(
        Ok(io::Cursor::new(other_inode)),
        &stat
    ));
}
