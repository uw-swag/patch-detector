import json
import os
from pprint import pprint

def BuildVulnerabilityMap():
  VulnerabilityDetails = {} #SNYK_ID:{package_name:XXX, version:XXX}
  with open('maven.json') as f:
    SNYKData = json.load(f)
    for package in SNYKData:
      for vulnerability in SNYKData[package]:
        #pprint(vulnerability)
        SNYK_ID = vulnerability['id']
        VulnerabilityDetails[SNYK_ID] = {}
        VulnerabilityDetails[SNYK_ID]['PackageName'] = package
        VulnerabilityDetails[SNYK_ID]['Version'] = [vulnerability_range for 
              vulnerability_range in vulnerability['semver']['vulnerable']]
  return VulnerabilityDetails

if __name__ == "__main__":
  vulnerabilityMap = BuildVulnerabilityMap()
  with open(os.path.join("experiments", "vulnerabilities", "VulnerabilityMap.json"), 'w') as f:
    json.dump(vulnerabilityMap, f, indent=4)
    