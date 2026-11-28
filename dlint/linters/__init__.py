from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from . import base  # noqa F401
from . import helpers  # noqa F401

from .bad_commands_use import BadCommandsUseLinter
from .bad_compile_use import BadCompileUseLinter
from .bad_cryptography_module_attribute_use import BadCryptographyModuleAttributeUseLinter
from .bad_defusedxml_use import BadDefusedxmlUseLinter
from .bad_dl_use import BadDlUseLinter
from .bad_duo_client_use import BadDuoClientUseLinter
from .bad_gl_use import BadGlUseLinter
from .bad_eval_use import BadEvalUseLinter
from .bad_exec_use import BadExecUseLinter
from .bad_hashlib_use import BadHashlibUseLinter
from .bad_input_use import BadInputUseLinter
from .bad_itsdangerous_kwarg_use import BadItsDangerousKwargUseLinter
from .bad_marshal_use import BadMarshalUseLinter
from .bad_onelogin_kwarg_use import BadOneLoginKwargUseLinter
from .bad_onelogin_module_attribute_use import BadOneLoginModuleAttributeUseLinter
from .bad_os_use import BadOSUseLinter
from .bad_popen2_use import BadPopen2UseLinter
from .bad_random_generator_use import BadRandomGeneratorUseLinter
from .bad_re_catastrophic_use import BadReCatastrophicUseLinter
from .bad_requests_use import BadRequestsUseLinter
from .bad_shelve_use import BadShelveUseLinter
from .bad_subprocess_use import BadSubprocessUseLinter
from .bad_ssl_module_attribute_use import BadSSLModuleAttributeUseLinter
from .bad_sys_use import BadSysUseLinter
from .bad_tarfile_use import BadTarfileUseLinter
from .bad_tempfile_use import BadTempfileUseLinter
from .bad_temporary_resource_use import (
    BadResourceBranchUseLinter,
    BadResourceCleanupUseLinter,
    BadResourceLifecycleUseLinter,
    BadSecurityCheckUseLinter,
    BadTempResourceUseLinter,
    BadTempResourceCheckLinter,
    BadTempResourceBranchUseLinter,
    BadTempResourceCleanupLinter,
    BadTempfileBranchUseLinter,
    BadTempfileCleanupUseLinter,
    BadTempfileResourceUseLinter,
    BadTemporaryFileCleanupLinter,
    BadTemporaryFileUseLinter,
    BadTemporaryResourceCheckLinter,
    BadTemporaryResourceBranchUseLinter,
    BadTemporaryResourceCleanupLinter,
    BadTemporaryResourceSafetyLinter,
    BadTemporaryResourceUseLinter,
    BranchCleanupLinter,
    BranchEvidenceLinter,
    ResourceBranchLinter,
    ResourceCheckLinter,
    ResourceCleanupLinter,
    ResourceLifecycleLinter,
    ResourceSafetyCheckLinter,
    SecurityCheckBranchLinter,
    SecurityCheckLinter,
    TempResourceBranchLinter,
    TempResourceCheckLinter,
    TempResourceCleanupLinter,
    TempResourceLifecycleLinter,
    TempResourceSafetyLinter,
    TempfileBranchLinter,
    TempfileCheckLinter,
    TempfileCleanupLinter,
    TemporaryResourceCheckLinter,
    TemporaryResourceBranchLinter,
    TemporaryResourceCleanupLinter,
    TemporaryResourceSafetyLinter,
    TemporaryFileBranchLinter,
    TemporaryFileCleanupLinter,
    TemporaryFileUseLinter,
    analyze_resource_branches,
    analyze_temporary_resources,
    collect_temporary_resource_evidence,
    set_resource_config,
)
from .bad_urllib3_module_attribute_use import BadUrllib3ModuleAttributeUseLinter
from .bad_urllib3_kwarg_use import BadUrllib3KwargUseLinter
from .bad_pickle_use import BadPickleUseLinter
from .bad_pycrypto_use import BadPycryptoUseLinter
from .bad_xml_use import BadXMLUseLinter
from .bad_xmlrpc_use import BadXmlrpcUseLinter
from .bad_xmlsec_module_attribute_use import BadXmlsecModuleAttributeUseLinter
from .bad_yaml_use import BadYAMLUseLinter
from .bad_zipfile_use import BadZipfileUseLinter

from .twisted.inlinecallbacks_yield_statement import InlineCallbacksYieldStatementLinter
from .twisted.returnvalue_in_inlinecallbacks import ReturnValueInInlineCallbacksLinter
from .twisted.yield_return_statement import YieldReturnStatementLinter


__all__ = [
    'BadTemporaryResourceUseLinter',
    'BadTempResourceUseLinter',
    'BadResourceCleanupUseLinter',
    'BadTempfileCleanupUseLinter',
    'BadTempfileBranchUseLinter',
    'BadTempfileResourceUseLinter',
    'BadTemporaryFileUseLinter',
    'BadTemporaryFileCleanupLinter',
    'BadTemporaryResourceCheckLinter',
    'BadTemporaryResourceCleanupLinter',
    'BadTemporaryResourceSafetyLinter',
    'BadTemporaryResourceBranchUseLinter',
    'BadTempResourceCheckLinter',
    'BadTempResourceCleanupLinter',
    'BadTempResourceBranchUseLinter',
    'BadResourceLifecycleUseLinter',
    'BadResourceBranchUseLinter',
    'BadSecurityCheckUseLinter',
    'TemporaryResourceCheckLinter',
    'TemporaryResourceCleanupLinter',
    'TemporaryResourceSafetyLinter',
    'TemporaryResourceBranchLinter',
    'TemporaryFileUseLinter',
    'TemporaryFileCleanupLinter',
    'TemporaryFileBranchLinter',
    'TempResourceCheckLinter',
    'TempResourceCleanupLinter',
    'TempResourceLifecycleLinter',
    'TempResourceSafetyLinter',
    'TempResourceBranchLinter',
    'TempfileCheckLinter',
    'TempfileCleanupLinter',
    'TempfileBranchLinter',
    'ResourceCleanupLinter',
    'ResourceLifecycleLinter',
    'ResourceSafetyCheckLinter',
    'ResourceCheckLinter',
    'ResourceBranchLinter',
    'SecurityCheckBranchLinter',
    'SecurityCheckLinter',
    'BranchCleanupLinter',
    'BranchEvidenceLinter',
    'analyze_resource_branches',
    'analyze_temporary_resources',
    'collect_temporary_resource_evidence',
    'set_resource_config',
]

__all__ += sorted(
    name for name in globals()
    if name.endswith('Linter') and name not in __all__
)

ALL = (
    BadCommandsUseLinter,
    BadCompileUseLinter,
    BadCryptographyModuleAttributeUseLinter,
    BadDefusedxmlUseLinter,
    BadDlUseLinter,
    BadDuoClientUseLinter,
    BadGlUseLinter,
    BadEvalUseLinter,
    BadExecUseLinter,
    BadHashlibUseLinter,
    BadInputUseLinter,
    BadItsDangerousKwargUseLinter,
    BadMarshalUseLinter,
    BadOneLoginKwargUseLinter,
    BadOneLoginModuleAttributeUseLinter,
    BadOSUseLinter,
    BadPopen2UseLinter,
    BadRandomGeneratorUseLinter,
    BadReCatastrophicUseLinter,
    BadRequestsUseLinter,
    BadShelveUseLinter,
    BadSSLModuleAttributeUseLinter,
    BadSysUseLinter,
    BadSubprocessUseLinter,
    BadTempfileUseLinter,
    BadTemporaryResourceUseLinter,
    BadTarfileUseLinter,
    BadUrllib3ModuleAttributeUseLinter,
    BadUrllib3KwargUseLinter,
    BadPickleUseLinter,
    BadPycryptoUseLinter,
    BadXMLUseLinter,
    BadXmlrpcUseLinter,
    BadXmlsecModuleAttributeUseLinter,
    BadYAMLUseLinter,
    BadZipfileUseLinter,
    InlineCallbacksYieldStatementLinter,
    ReturnValueInInlineCallbacksLinter,
    YieldReturnStatementLinter,
)
