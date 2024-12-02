import os

def rename_files_to_lowercase(directory_path):
  """Renames all files in the specified directory to lowercase.

  Args:
    directory_path: The path to the directory containing the files.
  """

  for filename in os.listdir(directory_path):
    src = os.path.join(directory_path, filename)
    dst = os.path.join(directory_path, filename.lower())
    if src != dst:
        print (f"Renaming {src} to {dst}")
        os.rename(src, dst)

if __name__ == '__main__':
  directory_path = input("Enter the directory path: ")
  rename_files_to_lowercase(directory_path)