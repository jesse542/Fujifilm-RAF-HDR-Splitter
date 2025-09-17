This is a Python program designed to split the HDR raw image RAF file that Fujifilm cameras produce when shooting in HDR mode. 

The structure of the RAF file is referenced in the libopenraw library found here: https://libopenraw.freedesktop.org/formats/raf/


I created this program because some guy on the DPReview forums was able to split an HDR RAF file for someone else, but he never provided source code so that other people could do the same. 

Requirements: 
      Python 3.13 or later.
      Call it from the terminal(Linux, Mac), Powershell(Win).

Usage: `python3 split_hdr_raf_v3.py image.RAF`

Example: 
  `python3 split_hdr_raw_v3.py DSCF7320.RAF`
  
Output:

    DSCF7320_part1.RAF
  
    DSCF7320_part2.RAF
  
    DSCF7320_part3.RAF
  
Split image files are saved to the same directory as the original.

