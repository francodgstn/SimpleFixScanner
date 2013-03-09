<?php
/*
 * Sample class usage
 */
$scanner = new SimpleFixScanner();
$scanner->scan();

/**
 * Simple trojan scanner to fix some tedious trojan, that
 * corrupt some files on the server.
 *
 * You can modify this code as you need, to add a new trojan fix
 * simply add a method that give in input a filepath and return
 * the appropriate exit status (see FixExitStatus class for details), and add the
 * trojan name and the method name to the fixList[] array for the callback.
 * See fix336988() for an example.
 *
 * Currently supported trojan:
 * - 336988 (Thanks to fatsouls32 - http://www.freestuff.gr/forums/viewtopic.php?t=64419 for 336988 regex fix)
 * - 68c8c7 method added by Brett
 *
 * @author Franco D'Agostino franco.dgstn@gmail.com
 *
 */
class SimpleFixScanner {
  var $fileTypeToScan = array('php','html','htm','tpl',);
	var $fixList = array(
		//'Scanner Regex Check'=>'devCheckRegex', //Use to check wich files are scannd
		'Trojan 336988' => 'fix336988',
		'Trojan 68c8c7' => 'fix68c8c7',

	);
	var $startTime;
	var $memoryLimit = "200M";
	var $maxExecutionTime = "300";
	var $docRoot;
	var $filesToScan;
	var $filesScannedCount = 0;
	var $filesFixed = array();


	/*
	 * Start Fix Functions
	 * Add your custom fix function here, then update the $fixList array.
	 * ========================================================================
	 */

	/**
	 * Return true, just for check if the regex works.
	 * @param unknown $path
	 */
	function devCheckRegex($path) {
		if(is_file($path))
			return true;
		else
			return false;
	}

	/**
	 * Check and fix file for:
	 * 336988 Trojan
	 * @param unknown $path
	 * @return FILE_FIXED if trojan foud and fixed; otherwise FILE_OK;
	 */
	function fix336988( $path ) {
		$fileFixed = false;
		$regexPaterns = array(
				"/#336988#(.*?)#\/336988#/ism", 			// php
				"/\<!--336988-->(.*?)\<!--\/336988-->/ism",	// html
				'#(/\*336988\*/).*?(/\*/336988\*/)#ism', 	//js
		);
		$data = file_get_contents($path);

		foreach ($regexPaterns as $regex) {
			if (preg_match($regex,$data)){
				// If foud, replace malicious code with empty string
				$data = preg_replace($regex,"",$data);
				$fileFixed =  FixExitStatus::FILE_FIXED;
			}
		}
		if ($fileFixed != FixExitStatus::FILE_OK)
			file_put_contents( $path, $data);

		return $fileFixed;
	}


	/**
	 * Check and fix file for:
	 * 68c8c7 Trojan
	 * @param unknown $path
	 * @return FILE_FIXED if trojan foud and fixed; otherwise FILE_OK;
	 */
	function fix68c8c7( $path ) {
		$fileFixed = false;
		$regexPaterns = array(
				"/#68c8c7#(.*?)#\/68c8c7#/ism",             // php
				"/\<!--68c8c7-->(.*?)\<!--\/68c8c7-->/ism", // html
				'#(/\*68c8c7\*/).*?(/\*/68c8c7\*/)#ism',    //js
		);
		$data = file_get_contents($path);

		foreach ($regexPaterns as $regex) {
			if (preg_match($regex,$data)){
				// If foud, replace malicious code with empty string
				$data = preg_replace($regex,"",$data);
				$fileFixed =  FixExitStatus::FILE_FIXED;
			}
		}
		if ($fileFixed != FixExitStatus::FILE_OK)
			file_put_contents( $path, $data);

		return $fileFixed;
	}

	/*
	 * End Fix Functions
	 * ========================================================================
	 */


	/**
	 * Wrapper for the scan process
	 * @see $this->doScan()
	 */
	function scan(){
		echo "<h3>Simple Fix Scanner</h3>";
		echo "<hr />";
		echo "<p>Prepare the scanner... ";
		$this->prepareScanner();
		echo "<i>done</i>";
		echo "<br><small>(Directory: " . $this->docRoot . ")</small></p>";

		// Do the scann process
		echo "<p>Do scan... ";
		$this->doScan();
		echo "<i>done</i></p>";

		// Echo scan results
		$fileFixedCount = count($this->filesFixed);
		if ( $fileFixedCount > 0  ){
			echo "<h4>Matches:</h4>";
			echo "<p>Fixed " . $fileFixedCount  . " of " . $this->filesScannedCount . " files scanned</p>";
			echo "<ul>";
			foreach($this->filesFixed as $item) {
				$exitStatus = FixExitStatus::translateExitStatus($item['exitStatus']);
				echo sprintf("<li>{$exitStatus} - <strong>{$item['fix']}</strong> was found in file {$item['file']}</li>"); ;
			}
			echo "</ul>";
		} else {
			echo "<h4>No match found.</h4>";
			echo "<p>{$this->filesScannedCount} file scanned.</p>";
		}

		$endtime = microtime(true);
		$totaltime = ($endtime - $this->startTime);
		echo "<p><small>Time elpased: ".$totaltime." seconds</small></p>";
	}


	/**
	 * Prepare the scanner
	 */
	function prepareScanner(){
		ini_set('memory_limit', $this->memoryLimit);
		ini_set('max_execution_time', $this->maxExecutionTime);
		$this->startTime = microtime(true);
		if (!$this->docRoot)
			$this->docRoot = $_SERVER['DOCUMENT_ROOT'];
		$this->filesToScan = $this->getFilesToScan($this->docRoot);
	}

	/**
	 * Execute the scan process
	 */
	function doScan() {
		foreach ($this->filesToScan as $search) {
			$this->filesScannedCount++;
			foreach ($this->fixList as $name => $method){
				$chekFile = call_user_func( array($this, $method), $search[0] );
				if ( $chekFile != FixExitStatus::FILE_OK )
					$this->filesFixed[] = array('fix' => $name, 'file' => $search[0], 'exitStatus' => $chekFile);
			}
		}
	}

	/**
	 * Helper to get the list of the files to scan
	 * @param unknown $rootDir Root directory to scan
	 * @return RegexIterator
	 */
	function getFilesToScan($rootDir){
		$directoryIterator = new RecursiveDirectoryIterator($rootDir);
		$iterator = new RecursiveIteratorIterator($directoryIterator);
		$regex ='/^.+\.(' .implode("|", $this->fileTypeToScan ) . ')$/i';
		$files = new RegexIterator($iterator, $regex, RecursiveRegexIterator::GET_MATCH);
		return $files;
	}

}


final class FixExitStatus {
	private function __constructor() {}
	// fix exit status
	const FILE_OK = 0;
	const FILE_FIXED = 1;
	const CANT_FIX = 2;

	public static function translateExitStatus($status) {
		switch ($status) {
			case FixExitStatus::FILE_OK:
				return "File is safe";
			break;
			case FixExitStatus::FILE_FIXED:
				return "File fixed";
			break;
			case FixExitStatus::CANT_FIX:
				return "Can't fix file";
			break;
		}



	}
}

?>
