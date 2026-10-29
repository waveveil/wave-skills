"""Read-only folder completeness audit; Python standard library only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys


def linked(path):
    info=path.lstat()
    return path.is_symlink() or bool(getattr(info,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400))


def scan(folder,deep):
    files=[]
    issues=[]
    stack=[folder]
    while stack:
        directory=stack.pop()
        try:
            entries=sorted(directory.iterdir(),key=lambda p:p.name.casefold())
        except OSError as exc:
            issues.append({'path':str(directory),'kind':'read_error','error':str(exc)})
            continue
        for path in entries:
            try:
                if linked(path):
                    issues.append({'path':str(path),'kind':'skipped_link'})
                elif path.is_file():
                    files.append(path)
                elif deep and path.is_dir():
                    stack.append(path)
            except OSError as exc:
                issues.append({'path':str(path),'kind':'read_error','error':str(exc)})
    return files,issues


def hash_file(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            digest.update(block)
    return digest.hexdigest()


def audit(root,extensions,deep=False,match='any',hashes=False):
    root=root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Root must be a directory')
    rows=[]
    root_issues=[]
    root_files=[]
    for folder in sorted(root.iterdir(),key=lambda p:p.name.casefold()):
        try:
            if linked(folder):
                root_issues.append({'path':str(folder),'kind':'skipped_link'})
                continue
            if folder.is_file():
                root_files.append(folder.name)
                continue
            if not folder.is_dir():
                continue
        except OSError as exc:
            root_issues.append({'path':str(folder),'kind':'read_error','error':str(exc)})
            continue
        files,issues=scan(folder,deep)
        found=set()
        inventory=[]
        for path in files:
            rel=str(path.relative_to(folder))
            try:
                size=path.stat().st_size
                ext=path.suffix.lower()
                matching_extensions={suffix for suffix in extensions if path.name.lower().endswith(suffix)} if size>0 else set()
                item={'path':rel,'extension':ext,'bytes':size,'matches':bool(matching_extensions),'matching_extensions':sorted(matching_extensions)}
                if size==0:
                    issues.append({'path':str(path),'kind':'empty_file'})
                if hashes:
                    item['sha256']=hash_file(path)
                if item['matches']:
                    found.update(matching_extensions)
                inventory.append(item)
            except OSError as exc:
                issues.append({'path':str(path),'kind':'read_error','error':str(exc)})
        complete=bool(found) if match=='any' else extensions.issubset(found)
        rows.append({'folder':folder.name,'complete':complete,'found_extensions':sorted(found),'missing_extensions':sorted(extensions-found) if match=='all' or not complete else [],'matching_files':sum(x['matches'] for x in inventory),'files':inventory,'issues':issues})
    return {'checked_at_utc':datetime.now(timezone.utc).isoformat(),'root':str(root),'scope':'descendant files per direct child folder' if deep else 'direct files per direct child folder','required_extensions':sorted(extensions),'match':match,'folder_count':len(rows),'complete_folders':sum(x['complete'] for x in rows),'missing_folders':[x['folder'] for x in rows if not x['complete']],'matching_file_count':sum(x['matching_files'] for x in rows),'file_count':sum(len(x['files']) for x in rows),'issue_count':len(root_issues)+sum(len(x['issues']) for x in rows),'root_files_not_audited':root_files,'root_issues':root_issues,'folders':rows,'validation':'extension and nonzero size only; document readability not verified'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--extensions',required=True,help='Comma-separated suffixes, e.g. .pdf,.doc,.docx')
    parser.add_argument('--match',choices=['any','all'],default='any')
    parser.add_argument('--deep',action='store_true')
    parser.add_argument('--hashes',action='store_true')
    parser.add_argument('--report',type=Path)
    parser.add_argument('--strict',action='store_true')
    args=parser.parse_args()
    suffixes={('.'+s.strip().lstrip('.')).lower() for s in args.extensions.split(',') if s.strip()}
    if not suffixes or any(not re.fullmatch(r'\.[a-z0-9][a-z0-9._+-]*',s) for s in suffixes):
        parser.error('Provide one or more valid file extensions')
    root=args.root.resolve(strict=True)
    if args.report and args.report.resolve().is_relative_to(root):
        parser.error('Write the report outside the audited root')
    result=audit(root,suffixes,args.deep,args.match,args.hashes)
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        summary={k:v for k,v in result.items() if k!='folders'}
        summary['report']=str(args.report.resolve())
        print(json.dumps(summary,ensure_ascii=False,indent=2))
    else:
        print(json.dumps(result,ensure_ascii=False,indent=2))
    return 1 if args.strict and (result['missing_folders'] or result['issue_count'] or result['folder_count']==0) else 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError) as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(2)
