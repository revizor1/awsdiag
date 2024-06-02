import json, glob, re, os, shutil


def regenerate_data():
    for d in glob.glob("data/*/"):
        shutil.rmtree(d)

    fh = []
    id_pattern = r"(?<=:)([\d]{12})(?=:)"
    for fn in glob.glob("data/*_*.json"):
        if not fn == fn.lower():
            continue
        with open(fn, "r") as json_file:
            j = json.load(json_file)
            if not isinstance(j, dict):
                print(f"Not a dictionary: {fn}")
                continue
            for k in j:
                if not re.search(id_pattern, k):
                    continue
                act = re.findall(id_pattern, k)[0]  # FIXME: what if ramresourceegress? Add [-1] account
                os.mkdir(f"data/{act}") if not os.path.exists(f"data/{act}") else None
                on = f"data/{act}/{fn.split('_')[-1]}"
                start = '{\n"'
                if on in fh:
                    start = ',\n"'
                else:
                    fh.append(on)
                with open(on, "a") as out_file:
                    out_file.write(start + k + '": ' + json.dumps(j[k]))  # TODO: detect duplicates/ fake dups
    for on in list(set(fh)):
        with open(on, "a") as out_file:
            out_file.write("\n}")


if __name__ == "__main__":
    regenerate_data()
