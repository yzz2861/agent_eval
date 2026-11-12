import pytest
import os
import json

from hypothesis.strategies import text

# We need to grab one text example from hypothesis to prime its cache.
text().example()

if os.path.isdir('tests/test_fixtures/'):
    # large integration tests are not shipped in sdist.
    # see https://github.com/python-hyper/hpack/commit/09dcf5a695266c35ff594605e79f472f224e7b7f
    # see https://github.com/python-hyper/hpack/issues/272

    # This pair of generator expressions are pretty lame, but building lists is a
    # bad idea as I plan to have a substantial number of tests here.
    story_directories = (
        os.path.join('tests/test_fixtures', d)
        for d in os.listdir('tests/test_fixtures')
    )
    story_files = (
        os.path.join(storydir, name)
        for storydir in story_directories
        for name in os.listdir(storydir)
        if 'raw-data' not in storydir
    )
    raw_story_files = (
        os.path.join('tests/test_fixtures/raw-data', name)
        for name in os.listdir('tests/test_fixtures/raw-data')
    )


    @pytest.fixture(scope='class', params=story_files)
    def story(request):
        """
        Provides a detailed HPACK story to test with.
        """
        with open(request.param, 'r', encoding='utf-8') as f:
            return json.load(f)


    @pytest.fixture(scope='class', params=raw_story_files)
    def raw_story(request):
        """
        Provides a detailed HPACK story to test the encoder with.
        """
        with open(request.param, 'r', encoding='utf-8') as f:
            return json.load(f)
