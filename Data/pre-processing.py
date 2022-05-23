# Python code to pre-process the dataset of GeoLife.
# Given the set of GPS coordinates, it returns the set of distances 
# covered by the various user trajectories.
#
# The results will be in two files, respectively for the (int) distances and
# (float) distances

from geopy.distance import distance
import pandas as pd

file = "./geolife.csv"
distance_int = "./dataInt.txt"
distance_float = "./dataFloat.txt"

def write (filename, l):
    with open(filename, 'w') as f:
        for item in l:
            f.write("%s\n" % item)

def main():
    df = pd.read_csv(file, header=None, low_memory=False)

    # Deletes uid and date_time columns
    df.drop(columns=[2, 4], inplace=True)
    df.drop(labels=0, axis=0, inplace=True)

    df.groupby(3)
    dist = []
    dist_to_write = []

    tid = df.loc[1, 3]
    df = df.reset_index()

    for idx, row in df.iterrows():
        if (df.loc[idx, 3] == tid):
            lat = df.loc[idx, 0]
            lon = df.loc[idx, 1]
            dist.append(tuple((lat, lon)))
        else:
            tid = df.loc[idx, 3]

            for i in range(0, len(dist)-1):
                d = distance(dist[i], dist[i+1]).m
                dist_to_write.append(d)
            dist.clear()

    # Distances Float
    dist_to_write = [round(num, 5) for num in dist_to_write]
    write (distance_float, dist_to_write)

    # Distances Int
    dist_int = [round(num) for num in dist_to_write]
    write (distance_int, dist_int)

if __name__ == "__main__":
    main()