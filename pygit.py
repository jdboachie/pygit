import argparse
import collections
import difflib
import enum
import hashlib
import operator
import os
import stat
import struct
import sys
import time
import urllib.request
import zlib


INDEXENTRY = collections.namedtuple('INDEXENTRY', [
    'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode',
    'uid', 'gid', 'size', 'sha1', 'flags', 'path',
])


def read_file(path: str) -> bytes:
    """Read contents of file at given path as bytes.

    Args:
        path (str): Path to file.

    Returns:
        bytes: Contents of file.
    """
    with open(path, 'rb') as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    """Write data bytes to file at given path.

    Args:
        path (str): Path to file.
        data (bytes): Data to write.
    """
    with open(path, 'wb') as f:
        f.write(data)


def read_index() -> None:
    """Read git index file and return list of INDEXENTRY objects.
    """
    try:
        data = read_file(os.path.join('.git', 'index'))
    except FileNotFoundError:
        return []
    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[:-20], 'invalid index checksum'
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    assert signature == b'DIRC', \
        'invalid index signature {}'.format(signature)
    assert version == 2, 'unknown index version {}'.format(version)
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        fields = struct.unpack(
            '!LLLLLLLLLL20sH',
            entry_data[i:fields_end]
        )
        path_end = entry_data.index(b'\x00', fields_end)
        path = entry_data[fields_end:path_end]
        entry = INDEXENTRY(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    assert len(entries) == num_entries
    return entries


def init(repo: str) -> None:
    """Create directory for repo and initialize .git directory.

    Args:
        repo (str): Name of repository.
    """
    os.mkdir(repo)
    os.mkdir(os.path.join(repo, '.git'))

    for name in ['objects', 'refs', 'refs/heads']:
        os.mkdir(os.path.join(repo, '.git', name))

    write_file(os.path.join(repo, '.git', 'HEAD'),
               b'ref: regs/heads/master')

    print(f'initialized empty repository: {repo}')


def hash_object(data: bytes, obj_type: str, write: bool = True) -> str:
    """Compute hash of object data of given type and write to object
    store if "write" is True. Return SHA-1 object hash as hex string.

    Args:
        data (bytes): data to store as object
        obj_type (str): type of object, i.e. "blob", "commit", "tree"
        write (bool, optional): Whether to write to object store. Defaults to True.

    Returns:
        str: SHA-1 object hash as hex string.
    """
    header = "{} {}".format(obj_type, len(data)).encode()
    full_data = header + b'\x00' + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    if write:
        path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))
    return sha1


def find_object(sha1_prefix: str) -> str:
    """Find object with given SHA-1 prefix and return path to object in
    object store if exists. Return None if no object found.

    Args:
        sha1_prefix (str): SHA-1 prefix of object to find.

    Returns:
        str: Path to object in object store if exists, else None.
    """
    if len(sha1_prefix) < 2:
        raise ValueError('hash prefix must be 2 or more characters')
    obj_dir = os.path.join('.git', 'objects', sha1_prefix[:2])
    rest = sha1_prefix[2:]
    objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]
    if not objects:
        raise ValueError('object {!r} not found'.format(sha1_prefix))
    if len(objects) >= 2:
        raise ValueError('multiple objects ({}) with prefix {!r}'.format(
            len(objects), sha1_prefix
        ))
    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix: str) -> str:
    """Read object with given SHA-1 prefix and returns tuple of
    (object_type, data_bytes), or raise ValueError if not found.

    Args:
        sha1_prefix (str): SHA-1 prefix of object to read.

    Returns:
        str: Object type.
    """
    path = find_object(sha1_prefix)
    full_data = zlib.decompress(read_file(path))
    null_index = full_data.index(b'\x00')
    header = full_data[:null_index]
    obj_type, size_str = header.decode().split()
    size = int(size_str)
    data = full_data[null_index + 1:]
    assert size == len(data), 'expected size {}, got {} bytes'.format(
        size, len(data)
    )
    return (obj_type, data)


def read_tree(sha1: str = None, data: bytes = None) -> list:
    """Read tree object with given SHA-1 (hex string) or data, and return list
    or (mode, path, sha1) tuples.

    Args:
        sha1 (str, optional): Defaults to None.
        data (bytes, optional): Defaults to None.

    Returns:
        list: entries of tree object.
    """
    if sha1 is not None:
        obj_type, data = read_object(sha1)
        assert obj_type == 'tree', f'expected tree object, got {obj_type}'
    elif data is None:
        raise TypeError('must specify "sha1" or "data"')
    i = 0
    entries = []

    for _ in range(1000):
        end = data.find(b'\x00', i)
        if end == -1:
            break
        mode_str, path = data[i:end].decode().split()
        mode = int(mode_str, base=8)
        digest = data[end + 1:end + 21]
        entries.append((mode, path, digest.hex()))
        i = end + 1 + 20
    return entries


def cat_file(mode: str, sha1_prefix: str) -> None:
    """Write the contents of (or info about) object with given SHA-1 prefix to
    stdout. If mode is 'commit', 'tree', or 'blob', print raw data bytes of
    object. If mode is 'size', print the size of the object. If mode is
    'type', print the type of the object. If mode is 'pretty', print a
    prettified version of the object.

    Args:
        mode (str): Mode of cat-file command.
        sha1_prefix (str): sha1 prefix of object to read.
    """
    obj_type, data = read_object(sha1_prefix)
    if mode in ['commit', 'tree', 'blob']:
        if obj_type != mode:
            raise ValueError('expected object type {}, got {}'.format(
                mode, obj_type
            ))
        sys.stdout.buffer.write(data)
    elif mode == 'size':
        print(len(data))
    elif mode == 'type':
        print(obj_type)
    elif mode == "pretty":
        if obj_type in ['commit', 'blob']:
            sys.stdout.buffer.write(data)
        elif obj_type == 'tree':
            for mode, path, sha1 in read_tree(data=data):
                type_str = 'tree' if stat.S_ISDIR(mode) else 'blob'
