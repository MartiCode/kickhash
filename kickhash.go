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
	"hash"
	"hash/crc32"
	"crypto/md5"
	"crypto/sha256"

	"github.com/zeebo/xxh3"
	"github.com/schollz/progressbar/v3"
	"github.com/dustin/go-humanize"
)


type fileDesc struct {
	Size	int64
	Hash	string
}


func findDuplicates(haystack map[string]fileDesc) map[string][]string {
	hashToFiles := make(map[string][]string)

	for filename, info := range haystack {
		key := fmt.Sprintf("%s:%d", info.Hash, info.Size)
		hashToFiles[key] = append(hashToFiles[key], filename)
	}

	duplicates := make(map[string][]string)
	for key, filenames := range hashToFiles {
		if len(filenames)>1 {
			duplicates[key] = filenames
		}
	}
	return duplicates
}


// Return a hasher object based on algorithm name (md5 being the default)
func CreateHasher(algo string) hash.Hash {
	if algo=="crc32" {
		return crc32.NewIEEE()
	}

	if algo=="xxhash64" {
		return xxh3.New()
	}

	if algo=="sha256" {
		return sha256.New()
	}

	return md5.New()
}


// Returns hexadecimal hash value of a file given as specific hasher
func CreateHashHex(inputFilePath string, hasher hash.Hash) (string, error) {
	var file, err = os.Open(inputFilePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher.Reset()
	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", err
	}

	var bytesHash = hasher.Sum(nil)
	return hex.EncodeToString(bytesHash[:]), nil
}




func main() {


	/*
	 * Process the command line and options
	 */


	// All config values
	config := struct{
		hashName	string
		verbose		bool
		forceUpdate	bool
		doHidden	bool
		doDupes		bool
		verify		bool
		hashAlgo	string
	}{
		// Two working modes: verify (expects to find a hash file and verify it against the files) or not (just compute all hashes and creates/overwrite a hash file)
		verify: false,
	}

	// Parse command line flags
	flag.StringVar(&config.hashName, "hashname", "hashes.csv", "Name of file that will record all hashes")
	flag.BoolVar(&config.verbose, "verbose", false, "Verbose mode")
	flag.BoolVar(&config.forceUpdate, "update", false, "Update the hash file even if an old one exists (will still report differences)")
	flag.BoolVar(&config.doHidden, "hidden", false, "Also process hidden files")
	flag.BoolVar(&config.doDupes, "dupes", false, "Find and show duplicate files")
	flag.StringVar(&config.hashAlgo, "hash", "md5", "Hash algorithm (autodetected if an existing hash file exists), one of: crc32, xxhash64, md5, sha256")
	flag.Parse()


	// Get directory to process, either command line or current working dir
	path := flag.Arg(0)
	if (path=="") {
		path, _ = os.Getwd()
	}
	path = filepath.Clean(path) + string(os.PathSeparator)
	
	// Verify the directory actually exists
	stat, err := os.Stat(path);
	if os.IsNotExist(err) || !stat.IsDir() {
		fmt.Println("Error! "+path+" is not a valid directory")
		os.Exit(1)
	}

	// location and name of reference hash file to read and/or write
	hashFileName := filepath.Join(path, config.hashName) 

	// Hash functiont to use
	config.hashAlgo = strings.ToLower(config.hashAlgo)
	if config.hashAlgo!="crc32" && config.hashAlgo!="xxhash64" && config.hashAlgo!="sha256" {
		config.hashAlgo = "md5"
	}



	if config.verbose {
		fmt.Println("Path to process is "+ path)
		fmt.Println("Hash file is "+hashFileName)
	}


	/*
	 * Open any existing hash reference file
	 */
	reference := make(map[string]fileDesc)
	file, err := os.Open(hashFileName)
	if err == nil {
		defer file.Close()

		if config.verbose {
			fmt.Println("Previous hash file found, checking changes against it...")
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

		config.verify = true // we have a valid reference file! switch to verify mode

		// Override hash algorithm based on hash values length that are in the CSV file
		for _, x := range reference {
			if len(x.Hash)==8 {
				config.hashAlgo = "crc32"
			} else if len(x.Hash)==16 {
				config.hashAlgo = "xxhash64"
			} else if len(x.Hash)==32 {
				config.hashAlgo = "md5"
			} else if len(x.Hash)==64 {
				config.hashAlgo = "sha256"
			} else {
				fmt.Println("Error: hashes in hash file are of the wrong format")
				os.Exit(2)
			}

			break // only need to do this once
		}

	} else {
		if config.verbose {
			fmt.Println("No existing hash file found, creating new one")
		}
	}


	if config.verbose {
		fmt.Println("Hash algorithm is "+config.hashAlgo)		
	}


    


	/*
	 * Walk the directory tree and compile a list of files
	 */	
	todo := make(map[string]fileDesc) // list of files found with their MD5 and size
	err = filepath.Walk(path,
		func(fileName string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Don't do directories or the hash file
			if info.IsDir() || config.hashName==info.Name() {
				return nil
			}

			// Also skip hidden files unless required
			if !config.doHidden {
				hidden, e := IsHiddenFile(fileName) 

				if hidden || e!=nil {
					return nil
				}
			}

			shortName := strings.TrimPrefix(fileName, path)
			todo[shortName] = fileDesc{ info.Size(), "" }

			return nil
	})

	if err != nil {
		fmt.Println("Error! Could not process directory "+ path)
		os.Exit(1)
	}


	/*
	 * Actually hash all the files and figure out the differences
	 */

	bar := progressbar.NewOptions(len(todo),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetDescription("Processing files"),
		progressbar.OptionShowCount(), progressbar.OptionSetPredictTime(false),
		progressbar.OptionSetMaxDetailRow(1))


	fileChanged, fileAdded, fileProblem := []string{}, []string{}, []string{} // All the files that appear to have been changed, added or had issues
	var total uint64 = 0
	hasher := CreateHasher(config.hashAlgo)
	
	for shortName, rec := range todo {

		bar.Add(1)
		if len(shortName)<=70 {
			bar.AddDetail("Hashing "+shortName)
		} else {
			bar.AddDetail("Hashing "+fmt.Sprintf("%.70s", filepath.Base(shortName)))
		}
		
		hashString, err := CreateHashHex(filepath.Join(path,shortName), hasher)

		if err != nil {
			fileProblem = append(fileProblem, shortName)
			continue
		}

		total+= uint64(rec.Size)
		todo[shortName] = fileDesc{ rec.Size, hashString }

		if config.verify {
			old, found := reference[shortName]
			if !found {
				fileAdded = append(fileAdded, shortName)
			} else {
				if old.Hash!=hashString || old.Size!=rec.Size {
					fileChanged = append(fileChanged, shortName)
				}
				delete(reference, shortName)
			}
		}

	}


	bar.Finish()
	fmt.Println() // progress bar seems to not add a line feed


	/*
	 * If not verifying, or if forced-update, write new hash file
	 */
	if (!config.verify || config.forceUpdate) && len(todo)>0 {

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
	if config.verify {

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

		if len(fileProblem)>0 {
			fmt.Println(len(fileProblem), "file(s) had errors:")
			for _, name := range fileProblem {
				fmt.Println(" ", name)
			}
		}

		if len(fileAdded)+len(fileChanged)+len(reference)==0 {
			fmt.Println("No change found")
		}

	}



	/**
	 * Show duplicates
	 */
	if config.doDupes {

		duplicates := findDuplicates(todo)

		if len(duplicates)==0 {
			fmt.Println("No duplicate files found")
		} else {
			fmt.Printf("Found %d groups of duplicate files:\n", len(duplicates))
			for _, filenames := range duplicates {
				fmt.Println("These files appear identical:")
				for _, f := range filenames {
					fmt.Println(" ", f)
				}
			}
		}
	}


	if config.verbose {
		fmt.Println("Hashed "+humanize.Bytes(total))
	}

}