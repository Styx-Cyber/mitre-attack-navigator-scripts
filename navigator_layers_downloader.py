import json
import attackcti
import os
import requests
import argparse

######### Edit the two arrays below
SOFTWARE_IDENTIFIERS = []
GROUPS_IDENTIFIERS = [
    "G0130",
    "G0025",
    "G0009",
    "G0035",
    "G0066",
    "G0117",
    "G0084",
    "G0125",
    "G0065",
    "G0045",
    "G0104",
    "G0027",
    "G0076",
    "G0134",
    "G0090",
    "G0138",
    "G0026",
    "G0016",
    "G0060",
    "G0074",
    "G0100",
    "G0004",
    "G0095",
    "G0059",
    "G0103",
    "G0121",
    "G0089",
    "G0131",
    "G0010",]
# GROUPS_IDENTIFIERS = []
#########

DOMAINS = ["enterprise", "mobile", "ics"]
ATTACK_TO_STIX_MAPPING = {"groups" : ["intrusion-set"], "software" : ["malware", "tool"]}
REQUESTS_SESSION = None
# ----------------------
# Util functions

class LayerInfo:
    LAYER_TYPES = {"S": "software",
    "G": "groups"}

    def __init__(self, id, domains):

        if id[0] not in self.LAYER_TYPES.keys():
            raise ValueError(f"The id {id} has not been recognized")
        self.id = id
        self.type = self.LAYER_TYPES[id[0]]

        for domain in domains:
            if domain not in DOMAINS:
                raise ValueError(f"The domain {domain} has not been recognized")

        self.domains = domains

    @classmethod
    def from_stix_block(self, stix_block):
        """Construct a LayerInfo from a STIX block"""
        if stix_block.type not in [item for sub_list in ATTACK_TO_STIX_MAPPING.values() for item in sub_list]: # Stix representation of Software and Groups, flatten the list of list
            raise TypeError("This STIX block doesn't describe a MITRE ATTACK Software or Group")
        if not stix_block.external_references:
            raise TypeError("This STIX block doesn't describe any MITRE ATTACK data")
        for external_reference in stix_block.external_references:
            if external_reference.source_name == "mitre-attack":
                return LayerInfo(external_reference.external_id, [domain.strip("-attack") for domain in stix_block.x_mitre_domains])
        raise TypeError("This STIX block doesn't describe any MITRE ATTACK data")

def is_stix_block_of_attack_id(stix_block, attack_id):
    for external_reference in stix_block.external_references:
        if external_reference.source_name == "mitre-attack" and external_reference.external_id == attack_id:
            return True
    return False

def download(url, file_path):
    global REQUESTS_SESSION
    try:
        r = REQUESTS_SESSION.get(url, allow_redirects=True)
    except AttributeError:
        # Initializes the Requests session, to improve download speed, and recall download
        REQUESTS_SESSION = requests.Session()
        return download(url=url, file_path=file_path)
        
    if not r.ok:
        if r.status_code == 404:
            raise FileNotFoundError("This layer is not available on MITRE ATTACK website yet !")
        else:
            raise ConnectionError(f"Download failed : HTTP code {r.status_code} !")

    # Check that it is a correct JSON file, because sometimes, a HTML file is downloaded instead
    try:
        json.loads(r.content)
    except json.JSONDecodeError:
        raise FileNotFoundError(f"The downloaded file is not a valid JSON layer !")

    with open(
        file_path,
        "wb",
    ) as output_json:
        output_json.write(r.content)
            


def download_info_layer(layer_info: LayerInfo, layers_path):
    is_fully_downloaded = True
    for layer_info_domain in layer_info.domains:
        download_path = f"{layers_path}/{layer_info_domain}/{layer_info.type}/{layer_info.id}.json"
        download_url = f"https://attack.mitre.org/{layer_info.type}/{layer_info.id}/{layer_info.id}-{layer_info_domain}-layer.json"
        try:
            download(
            url=download_url,
            file_path=download_path,
        )
            print(f"{layer_info.id}'s {layer_info_domain} layer downloaded in {download_path}.")

        except Exception as e:
            print(
            f"""An error occurred while downloading {layer_info.id}'s {layer_info_domain} layer : {e.args[0]}""")
            is_fully_downloaded = False
    return is_fully_downloaded

def extract_layer_info_from_stix_data(stix_json_data):
    """Extract and return LayerInfo classes from STIX external references"""
    ids = []
    for stix_block in stix_json_data:
        for external_reference in stix_block.external_references:
            if external_reference.source_name == "mitre-attack":
                ids.append(external_reference.external_id)
                break
    return ids


# ----------------------
# Parse CLI arguments
parser = argparse.ArgumentParser(
    allow_abbrev=False,
    description="""Download Software or Groups ATT&CK Navigator layers, from the official MITRE ATTACK website. 
    Software and Groups IDs selection can be given in parameters, or in the source code.""",
)
parser.add_argument(
    "--layers-path",
    help="Path of the folder where layers will be downloaded",
    default="./layers",
)
parser.add_argument(
    "--force-path",
    help="Allow downloading on an existing folder (can overwrite existing files)",
    action="store_const",
    const=1,
)

software_arg_group = parser.add_mutually_exclusive_group(required=True)
software_arg_group.add_argument(
    "--no-software",
    help="Don't download Software layers",
    action="store_const",
    const=1,
)
software_arg_group.add_argument(
    "--software-ids",
    help="Download Software layers from given IDs. IDs must be given as a list. If no IDs are detected, they are taken from the source code.",
    nargs="*",
)
software_arg_group.add_argument(
    "--all-software",
    help="Download all Software layers",
    action="store_const",
    const=1,
)
software_arg_group.add_argument(
    "--all-enterprise-software",
    help="Download all Enterprise Software layers",
    action="store_const",
    const=1,
)
software_arg_group.add_argument(
    "--all-mobile-software",
    help="Download all Mobile Software layers",
    action="store_const",
    const=1,
)
software_arg_group.add_argument(
    "--all-ics-software",
    help="Download all ICS Software layers",
    action="store_const",
    const=1,
)

group_arg_group = parser.add_mutually_exclusive_group(required=True)
group_arg_group.add_argument(
    "--no-groups",
    help="Don't download Groups layers",
    action="store_const",
    const=1,
)
group_arg_group.add_argument(
    "--groups-ids",
    help="Download Groups layers from given IDs. IDs must be given as a list. If no IDs are detected, they are taken from the source code.",
    nargs="*",
)
group_arg_group.add_argument(
    "--all-groups",
    help="Download all Groups layers",
    action="store_const",
    const=1,
)
group_arg_group.add_argument(
    "--all-enterprise-groups",
    help="Download all Enterprise Groups layers",
    action="store_const",
    const=1,
)
group_arg_group.add_argument(
    "--all-mobile-groups",
    help="Download all Mobile Groups layers",
    action="store_const",
    const=1,
)
group_arg_group.add_argument(
    "--all-ics-groups",
    help="Download all ICS Groups layers",
    action="store_const",
    const=1,
)
cli_arguments = parser.parse_args()

# ----------------------
# Check that there are some layers to be downloaded
if (cli_arguments.no_groups and cli_arguments.no_software) or (
    not cli_arguments.groups_ids
    and not cli_arguments.software_ids
    and not SOFTWARE_IDENTIFIERS
    and not GROUPS_IDENTIFIERS
):
    print("Nothing to download !\n")
    parser.print_help()
    exit(0)

# Check the layers path
if not os.path.exists(cli_arguments.layers_path):
    try:
        os.mkdir(cli_arguments.layers_path)
        print(f"""{cli_arguments.layers_path} folder created.""")
    except Exception as e:
        print(
            f"""Could not create layers folder {cli_arguments.layers_path} : {e.args}"""
        )
        exit(1)
elif cli_arguments.force_path:
    if not os.access(cli_arguments.layers_path, mode=os.W_OK):
        print("The given layers path is not writable by the current user.")
        exit(1)
else:
    print(
        f"The folder {cli_arguments.layers_path} already exists, and --force-path has not been given."
    )
    exit(1)

# Check / create layers subfolders
try:
    for domain in DOMAINS:
        subfolder_path = f"{cli_arguments.layers_path}/{domain}"
        if not os.path.exists(subfolder_path):
            os.mkdir(subfolder_path)
        elif not os.access(subfolder_path, mode=os.W_OK):
                raise PermissionError(f"{subfolder_path} is not writable by the current user.")

        for layer_type in LayerInfo.LAYER_TYPES.values():
            subsubfolder_path = subfolder_path + f"/{layer_type}"
            if not os.path.exists(subsubfolder_path):
                os.mkdir(subsubfolder_path)
            elif not os.access(subsubfolder_path, mode=os.W_OK):
                    raise PermissionError(f"{subsubfolder_path} is not writable by the current user.")
except Exception as e:
    print(
        f"""Check / create subfolder {subfolder_path} failed : {e.args}"""
    )
    exit(1)
# ----------------------

print("Initializing STIX CTI Client, this could take a while ...")
attack_cti_client = attackcti.attack_client()

# Software handling
# --------
stix_data = []
selected_software_domain = "all"
if cli_arguments.software_ids is not None:
    id_list = []
    # Get the id list from the source code
    if len(cli_arguments.software_ids) == 0:
        id_list = SOFTWARE_IDENTIFIERS
    else:
        id_list = cli_arguments.software_ids

    if len(id_list) != 0:
        all_software_stix_data = attack_cti_client.get_software()
        for one_stix_block_software in all_software_stix_data:
            for id in id_list:
                if is_stix_block_of_attack_id(one_stix_block_software, id):
                    stix_data += [one_stix_block_software]
                    id_list.remove(id)
                    break
            if len(id_list) == 0:
                break

        if len(id_list) != 0:
            print(f"""{", ".join(id_list)} Software IDs could not be found !""")

else:
    if cli_arguments.all_software:
            stix_data = attack_cti_client.get_software()
    elif cli_arguments.all_enterprise_software:
            stix_data = attack_cti_client.get_enterprise_malware()
            selected_software_domain = "enterprise"
    elif cli_arguments.all_mobile_software:
            stix_data = attack_cti_client.get_mobile_malware()
            selected_software_domain = "mobile"
    elif cli_arguments.all_ics_software:
            stix_data = attack_cti_client.get_ics_malware()
            selected_software_domain = "ics"

# Groups handling
# --------
selected_groups_domain = "all"
if cli_arguments.groups_ids is not None:
    id_list = []
    # Get the id list from the source code
    if len(cli_arguments.groups_ids) == 0:
        id_list = GROUPS_IDENTIFIERS
    else:
        id_list = cli_arguments.groups_ids

    if len(id_list) != 0:
        all_groups_stix_data = attack_cti_client.get_groups()
        for one_stix_block_groups in all_groups_stix_data:
            for id in id_list:
                if is_stix_block_of_attack_id(one_stix_block_groups, id):
                    stix_data += [one_stix_block_groups]
                    id_list.remove(id)
                    break
            if len(id_list) == 0:
                break

        if len(id_list) != 0:
            print(f"""{", ".join(id_list)} Groups IDs could not be found !""")

else:
    if cli_arguments.all_groups:
            stix_data += attack_cti_client.get_groups()
    elif cli_arguments.all_enterprise_groups:
            stix_data += attack_cti_client.get_enterprise_groups()
            selected_groups_domain = "enterprise"
    elif cli_arguments.all_mobile_groups:
            stix_data += attack_cti_client.get_mobile_groups()
            selected_groups_domain = "mobile"
    elif cli_arguments.all_ics_groups:
            stix_data += attack_cti_client.get_ics_groups()
            selected_groups_domain = "ics"

# --------
# Convert each STIX block to a LayerInfo
layer_info_download_list = []
for stix_block in stix_data:
    try:
        layer_info_download_list.append(LayerInfo.from_stix_block(stix_block))
    except TypeError as e:
        pass # STIX Block parsing error, it means that this is not a Software or a Group
    except Exception as e:
        print(f"A Software or Group could not be processed : {e.args[0]}")

# Filter only the selected domains, because there are some Software or Groups that have multiple domains
for layer_info in layer_info_download_list:
    if selected_groups_domain != "all" and layer_info.type == "groups":
        layer_info.domains = [selected_groups_domain]
    if selected_software_domain != "all" and layer_info.type == "software":
        layer_info.domains = [selected_software_domain]

# Prepare successful download count
number_of_groups_to_download = 0
number_of_software_to_download = 0
for layer_info in layer_info_download_list:
    if layer_info.type == "software":
        number_of_software_to_download +=1
    elif layer_info.type == "groups":
        number_of_groups_to_download += 1

print("---------------------")
print(f"{number_of_groups_to_download} Groups and {number_of_software_to_download} Software layers are going to be downloaded.")

# Download layers from LayerInfos
fully_successful_downloads = {}
for data_type in LayerInfo.LAYER_TYPES.values():
    fully_successful_downloads[data_type] = 0

for layer_info in layer_info_download_list:
    if download_info_layer(layer_info, cli_arguments.layers_path):
        fully_successful_downloads[layer_info.type] += 1

print("---------------------")
print(f"""{fully_successful_downloads["software"]}/{number_of_software_to_download} Software and {fully_successful_downloads["groups"]}/{number_of_groups_to_download} Groups Navigator layers were entirely downloaded !""")
print("All done !")
