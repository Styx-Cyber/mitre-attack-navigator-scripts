import re
import os
from json import JSONDecodeError
import argparse
from mitreattack.navlayers.core.layer import Layer
from mitreattack.navlayers.core.layout import Layout
from mitreattack.navlayers.core.legenditem import LegendItem

# ----------------------
# Util functions

def find_technique_in_layer(technique_id, layer):
    """Return the technique that matches the given id in layer, or None if not found"""
    for technique in layer.layer.techniques:
        if technique.techniqueID == technique_id:
            return technique
    return None

def get_layer_name(layer, file_name):
    try:
        return re.search("\([A-Z][0-9]{4}\)", layer.layer.name).group(0).strip("()") # Layer parsed name
    except AttributeError as e:
        print(f"""Could not parse the name of {file_name}, filename will be used instead.""")
        return file_name # Filename if failed

# ----------------------
# Parse CLI arguments
parser = argparse.ArgumentParser(description="Merge all the ATT&CK Navigator Layers from folders into one file. By default, the current folder is taken. Each technique score is added, and comments are merged. If a technique is disabled in a layer, it will be disabled in the merged layer too.")
parser.add_argument('--path', '-p', help='Paths to folders containing JSON ATT&CK layer files', nargs='*', default=["./"])
parser.add_argument('--recursive', '-r', help='Recursively search for JSON files in paths', action='store_const', const=1)
parser.add_argument('--output', '-o', help='Path of the output merged layer file', action='store', required=False, default="./merged_layers.json")
parser.add_argument('--force', '-f', help='Allow overwriting an existing merged layer file', action='store_const', required=False, const=1)
cli_arguments = parser.parse_args()

# Check file overwriting
if os.path.exists(cli_arguments.output) and not cli_arguments.force:
    print(f"""A merged layer file already exists in "{cli_arguments.output}", and --force has not been given !""")
    exit(1)
# ----------------------
# Import layers from each path
layers_to_filename_dict = {}

directories = []
if cli_arguments.recursive:
    for directory in cli_arguments.path:
        directories += [nested_entry[0] for nested_entry in os.walk(directory)]
else:
    directories = cli_arguments.path

for path in directories:
    layer_names = []
    layers_in_this_path = []
    print("################################")
    print(f"""Processing layers in "{path}" ...""")

    # Match json files in this path
    try:
        json_file_paths = [file for file in os.listdir(path) if file.endswith(".json")]
    except Exception as e:
        print(f"""Path "{path}" is invalid !""")
        continue

    for json_file_path in json_file_paths:
        try:
            new_layer = Layer()
            new_layer.from_file(f"{path}/{json_file_path}")
        except JSONDecodeError as e:
            print(f"""{json_file_path} is not a valid Navigator layer""")
            continue

        layers_in_this_path.append(new_layer)
        layers_to_filename_dict[new_layer] = json_file_path.split('.')[0]
        print(f"""{json_file_path} layer imported""")
    print(f"""{len(layers_in_this_path)} layers have ben imported from "{path}" """)

# ----------------------
# Merge layers
print("################################")
print("All layers have been imported, merging ...")
if len(layers_to_filename_dict) == 0:
    print("Nothing to do !")
    exit(0)

layers = list(layers_to_filename_dict.keys())
# Initialize techniques of layers, so that characteristics can easily be merged with other layers
for layer in layers:
    for technique in layer.layer.techniques:
        if technique.score is None:
            technique.score = 0
        if technique.comment is None:
            technique.comment = ""
        if technique.enabled is None:
            technique.enabled = True
            
# Pop the first layer of the list, and make it the the basis of the merged layer
merged_layer = layers.pop()
max_score = 0
number_of_techniques_disabled = 0

# Merge layers
for layer in layers:
    for this_layer_technique in layer.layer.techniques:
        merged_layer_technique = find_technique_in_layer(
            this_layer_technique.techniqueID, merged_layer
        )

        # The technique already exists in merged_layer, merge the characteristics
        if merged_layer_technique:

            # Add non empty scores
            if this_layer_technique.score:
                merged_layer_technique.score += this_layer_technique.score

            # Merge non empty comments
            if this_layer_technique.comment:
                merged_layer_technique.comment += "\n\n" + this_layer_technique.comment

            # Disable this technique in the merged layer if disabled in this layer
            if (
                this_layer_technique.enabled != None
                and not this_layer_technique.enabled
            ):
                merged_layer_technique.enabled = False

        # We have never seen this technique before, clone it from this layer to the merged_layer
        else:
            merged_layer.layer.techniques.append(this_layer_technique)

# Post merge process
for technique in merged_layer.layer.techniques:
    technique.showSubtechniques = False
    technique.color = ""

    if not technique.enabled:
        number_of_techniques_disabled += 1
    else:
        # Update the maximum score, used later for the color palette
        if technique.score > max_score:
            max_score = technique.score
        # Strip \n prefixes
        if technique.comment:
            technique.comment = technique.comment.strip()

# Set layer metadata
merged_layer.layer.description = (f"""ATT&CK Techniques used by {", ".join([get_layer_name(layer, filename) for layer, filename in layers_to_filename_dict.items()]).strip()}. Maximum score is {max_score}""")
merged_layer.layer.name = f"{len(layers_to_filename_dict)} layers merged"
merged_layer.layer.hideDisabled = True
merged_layer.layer.expandSubtechniques = False
merged_layer.layer.selectTechniquesAcrossTactics = True

merged_layer.layer.layout = Layout()
merged_layer.layer.layout.showAggregateScores = True
merged_layer.layer.layout.aggregateFunction = "max"
merged_layer.layer.layout.showID = False
merged_layer.layer.layout.showName = True
merged_layer.layer.layout.layout = "flat"
merged_layer.layer.layout.countUnscored = False
merged_layer.layer.sorting = 3  # Sort techniques by descending score
merged_layer.layer.gradient.colors = ["#ffffff00", "#ff6666ff"]
merged_layer.layer.gradient.minValue = 0
merged_layer.layer.gradient.maxValue = max_score
merged_layer.layer.legendItems.clear()
merged_layer.layer.legendItems.append(LegendItem("La plus fréquente", merged_layer.layer.gradient.colors[1]))
merged_layer.layer.legendItems.append(LegendItem("La moins fréquente", merged_layer.layer.gradient.colors[0]))


merged_layer.to_file(cli_arguments.output)
print(f"""Maximum score is {max_score}.""")
print(f"""{len(merged_layer.layer.techniques) - number_of_techniques_disabled}/{len(merged_layer.layer.techniques)} techniques enabled""")
print(f"""{len(layers_to_filename_dict)} layers merged in {cli_arguments.output}""")
print("All done !")