from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class RDSDeletionProtection(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instances have deletion_protection enabled"
        id = "CKV_CUSTOM_1"
        supported_resources = ['aws_db_instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        Looks for deletion_protection configuration in aws_db_instance:
        https://www.terraform.io/docs/providers/aws/r/db_instance.html
        """
        if 'deletion_protection' in conf:
            if conf['deletion_protection'][0] == True:
                return CheckResult.PASSED
        return CheckResult.FAILED


check = RDSDeletionProtection()