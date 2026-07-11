"""CloudSentry — AWS VPC / Network checks (4)."""

from __future__ import annotations

from models import CheckResult
from providers.aws.iam_checks import _throttled


def c_vpc_001(connector, meta):  # SSH 0.0.0.0/0
    def fn(c, m):
        ec2 = c.client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        bad = []
        for sg in sgs:
            for ip in sg.get("IpPermissions", []):
                if ip.get("FromPort") == 22 and ip.get("ToPort") == 22:
                    for rng in ip.get("IpRanges", []):
                        if rng.get("CidrIp") == "0.0.0.0/0":
                            bad.append(sg["GroupId"])
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No SG allows SSH from 0.0.0.0/0.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} SG(s) allow SSH from internet.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_vpc_002(connector, meta):  # RDP 0.0.0.0/0
    def fn(c, m):
        ec2 = c.client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        bad = []
        for sg in sgs:
            for ip in sg.get("IpPermissions", []):
                if ip.get("FromPort") == 3389 and ip.get("ToPort") == 3389:
                    for rng in ip.get("IpRanges", []):
                        if rng.get("CidrIp") == "0.0.0.0/0":
                            bad.append(sg["GroupId"])
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No SG allows RDP from 0.0.0.0/0.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} SG(s) allow RDP from internet.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_vpc_003(connector, meta):  # all traffic 0.0.0.0/0
    def fn(c, m):
        ec2 = c.client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        bad = []
        for sg in sgs:
            for ip in sg.get("IpPermissions", []):
                proto = ip.get("IpProtocol")
                if proto == "-1":
                    for rng in ip.get("IpRanges", []):
                        if rng.get("CidrIp") == "0.0.0.0/0":
                            bad.append(sg["GroupId"])
        if not bad:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="No fully-open SGs (0.0.0.0/0 all).",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(bad)} SG(s) allow ALL from internet.",
                           risk=m["risk"], remediation=m["remediation"], affected=bad,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


def c_vpc_004(connector, meta):  # VPC flow logs
    def fn(c, m):
        ec2 = c.client("ec2")
        vpcs = ec2.describe_vpcs()["Vpcs"]
        no_flow = []
        for v in vpcs:
            vid = v["VpcId"]
            fls = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vid]}])["FlowLogs"]
            if not fls:
                no_flow.append(vid)
        if not no_flow:
            return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                                status="PASS", severity=m["severity"], description="VPC Flow Logs enabled on all VPCs.",
                                cis_ref=m["cis"], owasp_ref=m["owasp"])
        return CheckResult(check_id=m["id"], name=m["name"], provider="aws", category=m["category"],
                           status="FAIL", severity=m["severity"], description=f"{len(no_flow)} VPC(s) without Flow Logs.",
                           risk=m["risk"], remediation=m["remediation"], affected=no_flow,
                           cis_ref=m["cis"], owasp_ref=m["owasp"])
    return _throttled(fn, connector, meta)


AWS_VPC_CHECKS = {
    "AWS-VPC-001": c_vpc_001, "AWS-VPC-002": c_vpc_002,
    "AWS-VPC-003": c_vpc_003, "AWS-VPC-004": c_vpc_004,
}
