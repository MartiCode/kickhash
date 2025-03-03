package main

import (
	"fmt"
	"flag"
	"os"
	"io"
	"strings"
	"strconv"
	"slices"
	"maps"
	"encoding/hex"
	"encoding/csv"
    "path/filepath"
    "crypto/md5"

    "github.com/schollz/progressbar/v3"
    "github.com/dustin/go-humanize"
)


type fileDesc struct {
	Size	int64
	Hash	string
}




func CreateMD5Hex(inputFilePath string) (string, error) {
	var file, err = os.Open(inputFilePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hash = md5.New()
	_, err = io.Copy(hash, file)
	if err != nil {
		return "", err
	}

	var bytesHash = hash.Sum(nil)
	return hex.EncodeToString(bytesHash[:]), nil
}




func main() {

	hashName := flag.String("hashname", "hashes.csv", "Name of file that will record all hashes")
	verbose :=  flag.Bool("verbose", false, "Verbose mode")
	forceUpdate := flag.Bool("update", false, "Update the hash file even if an old one exists (will still report differences)")
	flag.Parse()

	// Get directory to process
	path := flag.Arg(0)
	if (path=="") {
		path, _ = os.Getwd()
	}

	path = filepath.Clean(path) + string(os.PathSeparator)
	
	// Verify path exists
	stat, err := os.Stat(path);
	if os.IsNotExist(err) || !stat.IsDir() {
		fmt.Println("Error! "+path+" is not a valid directory")
		os.Exit(1)	
	}

	hashFileName := filepath.Join(path, *hashName) // location and name of reference hash file to read and/or write

	// Two working modes: verify (expects to find a hash file and verify it against the files) or not (just compute all hashes and creates/overwrite a hash file)
	verify := false

	if (*verbose) {
		fmt.Println("Path to process is "+ path)
		fmt.Println("Hash file is "+hashFileName)
	}



	/*
	 * Open any existing hash reference file
	 */
	reference := make(map[string]fileDesc)
	file, err := os.Open(hashFileName)
    if err == nil {
    	if *verbose {
    		fmt.Println("Previous hash file found, checking changes...")
    	}

    	reader := csv.NewReader(file)
    	reader.Comma = '\t'
        lines, err := reader.ReadAll()
        if err!=nil {
        	fmt.Println("Error: cannot read existing hash file")
        	os.Exit(2)
        }
        for _, line := range lines {
        	size, err := strconv.ParseInt(line[1], 10, 64)
        	if (err!=nil) {
        		fmt.Println("Error: there was a problem decoding existing hash file")
        		os.Exit(2)
        	}
        	reference[line[0]] = fileDesc{ size, line[2]  }
        }

        verify = true // we have a valid reference file! switch to verify mode
    } else {
    	if *verbose {
    		fmt.Println("No existing hash file found, creating new one")
    	}
    }
    defer file.Close()



    /*
	 * Walk the directory
	 */
	
	todo := make(map[string]fileDesc) // list of files found with their MD5 and size
	

	// Explore directory tree and collect list of files
	err = filepath.Walk(path,
		func(fileName string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if (!info.IsDir() && *hashName!=info.Name()) {
				shortName := strings.TrimPrefix(fileName, path)
				todo[shortName] = fileDesc{ info.Size(), "" }

			}

			return nil
	})

	if err != nil {
		fmt.Println("Error! Could not process directory "+ path)
		os.Exit(1)
	}


	bar := progressbar.NewOptions(len(todo),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetDescription("Processing files"),
		progressbar.OptionShowCount(), progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetMaxDetailRow(1))


	fileChanged, fileAdded, fileProblem := []string{}, []string{}, []string{} // All the files that appear to have been changed, added or had issues
	var total uint64 = 0
	for shortName, rec := range todo {

		bar.Add(1)
		bar.AddDetail("Hashing "+shortName)
		md5, err := CreateMD5Hex(path + shortName)

		if err != nil {
			fileProblem = append(fileProblem, shortName)
		}

		total+= uint64(rec.Size)
		todo[shortName] = fileDesc{ rec.Size, md5 }

		if verify {
			old, found := reference[shortName]
			if !found {
				fileAdded = append(fileAdded, shortName)
			} else {
				if old.Hash!=md5 || old.Size!=rec.Size {
					fileChanged = append(fileChanged, shortName)
				}
				delete(reference, shortName)
			}

		}

	}


/*
	err = filepath.Walk(path,
		func(fileName string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if (!info.IsDir() && *hashName!=info.Name()) {
			
				shortName := strings.TrimPrefix(fileName, path)

				bar.Add(1)
				bar.AddDetail("Hashing "+shortName)
				md5, err := CreateMD5Hex(fileName)

				if err != nil {
					fileProblem = append(fileProblem, shortName)
				}

				total+= uint64(info.Size())

				if verify {
					old, found := reference[shortName]
					if !found {
						fileAdded = append(fileAdded, shortName)
					} else {
						if old.Hash!=md5 || old.Size!=info.Size() {
							fileChanged = append(fileChanged, shortName)
						}
						delete(reference, shortName)
					}

				}
			
				todo[shortName] = fileDesc{ info.Size(), md5 }
			}
		
			return nil
	})


	if err != nil {
		fmt.Println("Error! Could not process directory "+ path)
		os.Exit(1)
	}
*/
	


	bar.Finish()
	fmt.Println("") // progress bar seems to not add a line feed


	/*
	 * If not verifying or forced, write new hash file
	 */
	if (!verify || *forceUpdate) && len(todo)>0 {

		file, err = os.Create(hashFileName)
		if err != nil {
	    	fmt.Println("Error! Could not create hash file "+ hashFileName)
	    	os.Exit(3)
		}

		writer := csv.NewWriter(file)
		writer.Comma = '\t'
		defer writer.Flush()

		// Sort by filenames so we can have a sorted CSV output
		sortedFileNames := slices.Sorted(maps.Keys(todo))
		for _, fileName := range sortedFileNames {
			err := writer.Write([]string{ strings.TrimPrefix(fileName, path), strconv.FormatInt(todo[fileName].Size,10), todo[fileName].Hash });
			if err!=nil {
				fmt.Println("Error! Could not write hash file "+ hashFileName)
				os.Exit(3)
			}
		}

	}


	/**
	 * If verifying, show result of comparison
	 */
	if verify {

		if len(fileAdded)>0 {
			fmt.Println(len(fileAdded), " file(s) are new:")
			for _, name := range fileAdded {
				fmt.Println(" ", name)
			}
		}

		if len(fileChanged)>0 {
			fmt.Println(len(fileChanged), " file(s) are different:")
			for _, name := range fileChanged {
				fmt.Println(" ", name)
			}
		}

		if len(reference)>0 {
			fmt.Println(len(reference), " file(s) have been removed:")
			for name, _ := range reference {
				fmt.Println(" ", name)
			}
		}

		if len(fileAdded)+len(fileChanged)+len(reference)==0 {
			fmt.Println("No change found")
		}

	}

	if *verbose {
		fmt.Println("Hashed "+humanize.Bytes(total))
	}


}