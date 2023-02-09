import glob
import re
from json import JSONDecodeError
import argparse
from mitreattack.navlayers.core.layer import Layer
from mitreattack.navlayers.core.layout import Layout
from mitreattack.navlayers.core.legenditem import LegendItem

def find_technique_in_layer(technique_id, layer):
    """Return the technique that matches the given id in layer, or None if not found"""
    for technique in layer.layer.techniques:
        if technique.techniqueID == technique_id:
            return technique
    return None

# Parse path argument
parser = argparse.ArgumentParser()
parser.add_argument('--path', help='path to a folder containing JSON ATT&CK layer files', action='append', required=True)
cli_arguments = parser.parse_args()


# Import layers from JSON files
for path in cli_arguments.path:
    layers = []
    masks = []
    layer_names = []
    print("################################")
    print("Processing layers in " + path + "...")

    # Match groups and custom-made json layer files
    json_files_paths = glob.glob(path.strip('/') + "/[A-Z]????.json")
    json_files_paths.extend(glob.glob(path.strip('/') + "/CUSTOM*.json"))

    for json_file_path in json_files_paths:
        try:
            new_layer = Layer()
            new_layer.from_file(json_file_path)
        except JSONDecodeError as e:
            print(f"""Could not import {json_file_path}""")
            exit(1)

        layers.append(new_layer)
        print(f"""{json_file_path} layer imported""")

        try:
            layer_names.append(re.search("[A-Z][0-9]{4}", new_layer.layer.description).group(0))
        except AttributeError as e:
            print(f"""Could not parse the name of {json_file_path}, filename will be used instead.""")
            file_name = json_file_path.replace('\\', '/').split('/')[-1]
            layer_names.append(file_name)

    # Sip this path if no layers have been imported
    if not len(layers):
        print("No layers have been imported in this path, skipping ...")
        continue
    else:
        print(f"""{len(layers)} layers have ben imported.""")

    # Initialize techniques of layers, so that characteristics can easily be merged with other layers
    for layer in layers:
        for technique in layer.layer.techniques:
            if technique.score is None:
                technique.score = 0
            if technique.comment is None:
                technique.comment = ""
            if technique.enabled is None:
                technique.enabled = True
                
    # Pop the first layer of the list, and make it the merged layer
    merged_layer = layers.pop()
    max_score = 1
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
    merged_layer.layer.description = (f"""ATT&CK Techniques used by {", ".join(layer_names).strip()}""")
    merged_layer.layer.name = "Matrix of aggregated techniques"
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


    merged_layer.to_file(path.strip('/') + "/processed.json")  # Save merged layer to a file
    print(f"""Maximum score is {max_score}.""")
    print(f"""{len(merged_layer.layer.techniques) - number_of_techniques_disabled}/{len(merged_layer.layer.techniques)} techniques enabled""")
    print(f"""{len(layers) + 1} layers merged in {path.strip('/')}/processed.json""")
