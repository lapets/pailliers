=========
pailliers
=========

Minimal pure-Python implementation of `Paillier's additively homomorphic cryptosystem <https://en.wikipedia.org/wiki/Paillier_cryptosystem>`__.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/pailliers.svg#
   :target: https://badge.fury.io/py/pailliers
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/pailliers/badge/?version=latest
   :target: https://pailliers.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/lapets/pailliers/workflows/lint-test-cover-docs/badge.svg#
   :target: https://github.com/lapets/pailliers/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/lapets/pailliers/badge.svg?branch=main
   :target: https://coveralls.io/github/lapets/pailliers?branch=main
   :alt: Coveralls test coverage summary.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/pailliers>`__:

.. code-block:: bash

    python -m pip install pailliers

The library can be imported in the usual manner:

.. code-block:: python

    from pailliers import *

Examples
^^^^^^^^

.. |secret| replace:: ``secret``
.. _secret: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.secret

.. |public| replace:: ``public``
.. _public: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.public

.. |encrypt| replace:: ``encrypt``
.. _encrypt: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.encrypt

.. |decrypt| replace:: ``decrypt``
.. _decrypt: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.decrypt


This library supports the creation of |secret|_ keys, derivation of |public|_ keys from |secret|_ keys, encryption of integers into ciphertexts using public keys via |encrypt|_, and decryption of ciphertexts into integers using |secret|_ keys via |decrypt|_:

.. code-block:: python

    >>> secret_key = secret(2048)
    >>> public_key = public(secret_key)
    >>> c = encrypt(public_key, 123)
    >>> int(decrypt(secret_key, c))
    123

.. |cipher| replace:: ``cipher``
.. _cipher: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.cipher

.. |int| replace:: ``int``
.. _int: https://docs.python.org/3/library/functions.html#int

.. |special_add| replace:: ``__add__``
.. _special_add: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.cipher.__add__

.. |special_mul| replace:: ``__mul__``
.. _special_mul: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.cipher.__mul__

The |encrypt|_ function returns instances of the |cipher|_ class (which is `derived <https://docs.python.org/3/tutorial/classes.html#inheritance>`__ from the built-in |int|_ type) that represent ciphertexts. Because the |cipher|_ class includes definitions of special methods (such as |special_add|_ and |special_mul|_) corresponding to Python's built-in addition and multiplication operators, these operators can be used to add two ciphertexts and to multiply a ciphertext by an integer scalar:

.. code-block:: python

    >>> c = encrypt(public_key, 123)
    >>> d = encrypt(public_key, 456)
    >>> r = (c * 2) + d
    >>> int(decrypt(secret_key, r))
    702

.. |special_iadd| replace:: ``__iadd__``
.. _special_iadd: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.cipher.__iadd__

.. |special_imul| replace:: ``__imul__``
.. _special_imul: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.cipher.__imul__

.. |special_radd| replace:: ``__radd__``
.. _special_radd: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.cipher.__radd__

.. |sum| replace:: ``sum``
.. _sum: https://docs.python.org/3/library/functions.html#sum

Other special methods make it possible to use a single variable to accumulate iteratively (via |special_iadd|_ and |special_imul|_) and to use the built-in |sum|_ function (via |special_radd|_):

.. code-block:: python

    >>> b = 0
    >>> b += encrypt(public_key, 1)
    >>> b += encrypt(public_key, 2)
    >>> b += encrypt(public_key, 3)
    >>> b *= 2
    >>> b = sum([b, b, b])
    >>> int(decrypt(secret_key, b))
    36

.. |add| replace:: ``add``
.. _add: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.add

.. |mul| replace:: ``mul``
.. _mul: https://pailliers.readthedocs.io/en/0.3.0/_source/pailliers.html#pailliers.pailliers.mul

Addition will only work on two or more instances of the |cipher|_ class. To facilitate the use of |cipher|_ instances that do not all maintain internal copies of the same public key (*e.g.*, in cases where memory constraints are an issue or ciphertexts are stored/communicated separately from key information), the |add|_ and |mul|_ functions are also provided. The public key must be supplied explicitly to these functions:

.. code-block:: python

    >>> c = int(encrypt(public_key, 123))
    >>> d = int(encrypt(public_key, 456))
    >>> r = mul(public_key, cipher(c), 2)
    >>> s = add(public_key, r, cipher(d))
    >>> int(decrypt(secret_key, s))
    702

An alternative to the above is to instantiate |cipher|_ instances using explicit ciphertext values and the public key used to encrypt them:

.. code-block:: python

    >>> c = int(encrypt(public_key, 123))
    >>> d = int(encrypt(public_key, 456))
    >>> c = cipher(c, public_key)
    >>> d = cipher(d, public_key)
    >>> s = (2 * c) + d
    >>> int(decrypt(secret_key, s))
    702

Development
-----------
All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__:

.. code-block:: bash

    python -m pip install ".[docs,lint]"

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    python -m pip install ".[docs]"
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details):

.. code-block:: bash

    python -m pip install ".[test]"
    python -m pytest

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__:

.. code-block:: bash

    python src/pailliers/pailliers.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install ".[lint]"
    python -m pylint src/pailliers

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/lapets/pailliers>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/pailliers>`__ via the GitHub Actions workflow found in ``.github/workflows/build-publish-sign-release.yml`` that follows the `recommendations found in the Python Packaging User Guide <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>`__.

Ensure that the correct version number appears in ``pyproject.toml``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.

To publish the package, create and push a tag for the version being published (replacing ``?.?.?`` with the version number):

.. code-block:: bash

    git tag ?.?.?
    git push origin ?.?.?
