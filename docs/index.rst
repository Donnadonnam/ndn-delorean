NDN DeLorean: An Authentication System for Data Archives in Named Data Networking
=================================================================================

Named Data Networking (NDN) enables data-centric security in network communication by mandating digital signatures on network-layer data packets. Since the lifetime of some data can extend to many years, they out-live the lifetime of their signatures.

*NDN DeLorean* is an authentication framework to ensure the long-term authenticity of long-lived data, taking a publicly auditable bookkeeping service approach to keep permanent proofs of data signatures and the times the signatures were generated.

NSL Documentation
-----------------

.. toctree::
   :hidden:
   :maxdepth: 3

   INSTALL
   manpages
   design

- :doc:`README`

- :doc:`INSTALL`

- :doc:`manpages`

- :doc:`design`

Documentation for ndn-cxx developers and contributors
+++++++++++++++++++++++++++++++++++++++++++++++++++++

- `API documentation (doxygen) <doxygen/annotated.html>`_

License
-------

NDN DeLorean is an open source project licensed under conditions of GNU Lesser General Public License. For more information about the license, refer to `COPYING <https://github.com/named-data/nsl/blob/master/COPYING>`_.

While the license does not require it, we really would appreciate it if others would share their contributions to the library if they are willing to do so under the same license.
