# Natural Language Toolkit: staging scratch directory security
#
# Copyright (C) 2001-2026 NLTK Project
# URL: <https://www.nltk.org/>
# For license information, see LICENSE.TXT

"""``nltk.data.staging_tempdir`` must stay inside a data root for its whole life.

The wrappers that shell out to an external tool stage an input file first.
Those used to go to the system temp dir, which on Linux is the shared,
world-writable ``/tmp`` and is deliberately not a pathsec root, so the scratch
file landed outside the sandbox. ``staging_tempdir`` fixes that by allocating a
0700 directory inside a data root.

Because it caches that directory in a module global, the cache is only as
trustworthy as the directory it names, which is what these tests attack.
"""

import os
import shutil


class TestStagingDirLifetime:
    """make_staging_dir leaked a directory per call for every caller but one.

    The name is unpredictable, so nothing can find it again to clean up: 70 had
    accumulated under the data root on a development machine. Cleanup is opt-in
    rather than automatic because some callers stage a *saved model* there, and
    deleting the user's artifact at exit would be surprising.
    """

    def _run(self, script):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
        )
        assert result.returncode == 0, result.stderr
        return dict(
            line.split("=", 1)
            for line in result.stdout.strip().splitlines()
            if line.startswith("D")
        )

    def test_cleanup_true_removes_the_dir_at_exit(self):
        paths = self._run(
            "import nltk.data;"
            "print('D=' + nltk.data.make_staging_dir("
            "prefix='nltk_cleanup_t_', cleanup=True))"
        )
        assert not os.path.exists(paths["D"])

    def test_cleanup_defaults_to_keeping_the_dir(self):
        """A saved model must survive the interpreter exiting."""
        paths = self._run(
            "import nltk.data;"
            "print('D=' + nltk.data.make_staging_dir(prefix='nltk_cleanup_f_'))"
        )
        try:
            assert os.path.exists(paths["D"])
        finally:
            shutil.rmtree(paths["D"], ignore_errors=True)
