<?php
/********************************
Simple PHP File Manager
Copyright John Campbell (jcampbell1)

Liscense: MIT
********************************/

//Disable error report for undefined superglobals
error_reporting( error_reporting() & ~E_NOTICE );

//Security options
$allow_delete = true; // Set to false to disable delete button and delete POST request.
$allow_upload = true; // Set to true to allow upload files
$allow_create_folder = true; // Set to false to disable folder creation
$allow_direct_link = true; // Set to false to only allow downloads and not direct link
$allow_show_folders = true; // Set to false to hide all subdirectories

$disallowed_patterns = ['*.php'];  // must be an array.  Matching files not allowed to be uploaded
$hidden_patterns = ['*.php','.*']; // Matching files hidden in directory index

$PASSWORD = 'password';  // Set the password, to access the file manager... (optional)

if($PASSWORD) {

	session_start();
	if(!$_SESSION['_sfm_allowed']) {
		// sha1, and random bytes to thwart timing attacks.  Not meant as secure hashing.
		$t = bin2hex(openssl_random_pseudo_bytes(10));
		if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
			$_SESSION['_sfm_allowed'] = true;
			header('Location: ?');
		}
		echo '<html><body><form action=? method=post>Please enter your password:<input type=password name=p autofocus/></form></body></html>';
		exit;
	}
}

// must be in UTF-8 or `basename` doesn't work
setlocale(LC_ALL,'en_US.UTF-8');

$tmp_dir = dirname($_SERVER['SCRIPT_FILENAME']);
if(DIRECTORY_SEPARATOR==='\\') $tmp_dir = str_replace('/',DIRECTORY_SEPARATOR,$tmp_dir);
$tmp = get_absolute_path($tmp_dir . '/' .$_REQUEST['file']);

if($tmp === false)
	err(404,'File or Directory Not Found');
if(substr($tmp, 0,strlen($tmp_dir)) !== $tmp_dir)
	err(403,"Forbidden");
if(strpos($_REQUEST['file'], DIRECTORY_SEPARATOR) === 0)
	err(403,"Forbidden");
if(preg_match('@^.+://@',$_REQUEST['file'])) {
	err(403,"Forbidden");
}


if(!$_COOKIE['_sfm_xsrf'])
	setcookie('_sfm_xsrf',bin2hex(openssl_random_pseudo_bytes(16)));
if($_POST) {
	if($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
		err(403,"XSRF Failure");
}

$file = $_REQUEST['file'] ?: '.';

if($_GET['do'] == 'list') {
	if (is_dir($file)) {
		$directory = $file;
		$result = [];
		$files = array_diff(scandir($directory), ['.','..']);
		foreach ($files as $entry) if (!is_entry_ignored($entry, $allow_show_folders, $hidden_patterns)) {
			$i = $directory . '/' . $entry;
			$stat = stat($i);
			$result[] = [
				'mtime' => $stat['mtime'],
				'size' => $stat['size'],
				'name' => basename($i),
				'path' => preg_replace('@^\./@', '', $i),
				'is_dir' => is_dir($i),
				'is_deleteable' => $allow_delete && ((!is_dir($i) && is_writable($directory)) ||
														(is_dir($i) && is_writable($directory) && is_recursively_deleteable($i))),
				'is_readable' => is_readable($i),
				'is_writable' => is_writable($i),
				'is_executable' => is_executable($i),
			];
		}
		usort($result,function($f1,$f2){
			$f1_key = ($f1['is_dir']?:2) . $f1['name'];
			$f2_key = ($f2['is_dir']?:2) . $f2['name'];
			return $f1_key > $f2_key;
		});
	} else {
		err(412,"Not a Directory");
	}
	echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' =>$result]);
	exit;
} elseif ($_POST['do'] == 'delete') {
	if($allow_delete) {
		rmrf($file);
	}
	exit;
} elseif ($_POST['do'] == 'mkdir' && $allow_create_folder) {
	// don't allow actions outside root. we also filter out slashes to catch args like './../outside'
	$dir = $_POST['name'];
	$dir = str_replace('/', '', $dir);
	if(substr($dir, 0, 2) === '..')
	    exit;
	chdir($file);
	@mkdir($_POST['name']);
	exit;
} elseif ($_POST['do'] == 'upload' && $allow_upload) {
	foreach($disallowed_patterns as $pattern)
		if(fnmatch($pattern, $_FILES['file_data']['name']))
			err(403,"Files of this type are not allowed.");

	$res = move_uploaded_file($_FILES['file_data']['tmp_name'], $file.'/'.$_FILES['file_data']['name']);
	exit;
} elseif ($_GET['do'] == 'download') {
	foreach($disallowed_patterns as $pattern)
		if(fnmatch($pattern, $file))
			err(403,"Files of this type are not allowed.");

	$filename = basename($file);
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	header('Content-Type: ' . finfo_file($finfo, $file));
	header('Content-Length: '. filesize($file));
	header(sprintf('Content-Disposition: attachment; filename=%s',
		strpos('MSIE',$_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\"" ));
	ob_flush();
	readfile($file);
	exit;

    // listen to the rename event
}elseif ($_GET['do'] == 'rename'){
    // validate if the file name is FileToBeRenamed.txt
    if($file == 'FileToBeRenamed.txt'){
        // get the path
        $dir_father = dirname(__FILE__);
        //file exist
        if(file_exists($dir_father.'/'.'FileToBeRenamed.txt')){
            // rename FileToBeRenamed.txt file to FileRenamed.txt
            rename($dir_father.'/'.'FileToBeRenamed.txt','FileRenamed.txt');
        }

    }
}

function is_entry_ignored($entry, $allow_show_folders, $hidden_patterns) {
	if ($entry === basename(__FILE__)) {
		return true;
	}

	if (is_dir($entry) && !$allow_show_folders) {
		return true;
	}
	foreach($hidden_patterns as $pattern) {
		if(fnmatch($pattern,$entry)) {
			return true;
		}
	}
	return false;
}

function rmrf($dir) {
	if(is_dir($dir)) {
		$files = array_diff(scandir($dir), ['.','..']);
		foreach ($files as $file)
			rmrf("$dir/$file");
		rmdir($dir);
	} else {
		unlink($dir);
	}
}
function is_recursively_deleteable($d) {
	$stack = [$d];
	while($dir = array_pop($stack)) {
		if(!is_readable($dir) || !is_writable($dir))
			return false;
		$files = array_diff(scandir($dir), ['.','..']);
		foreach($files as $file) if(is_dir($file)) {
			$stack[] = "$dir/$file";
		}
	}
	return true;
}

// from: http://php.net/manual/en/function.realpath.php#84012
function get_absolute_path($path) {
        $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
        $parts = explode(DIRECTORY_SEPARATOR, $path);
        $absolutes = [];
        foreach ($parts as $part) {
            if ('.' == $part) continue;
            if ('..' == $part) {
                array_pop($absolutes);
            } else {
                $absolutes[] = $part;
            }
        }
        return implode(DIRECTORY_SEPARATOR, $absolutes);
    }

function err($code,$msg) {
	http_response_code($code);
	header("Content-Type: application/json");
	echo json_encode(['error' => ['code'=>intval($code), 'msg' => $msg]]);
	exit;
}

function asBytes($ini_v) {
	$ini_v = trim($ini_v);
	$s = ['g'=> 1<<30, 'm' => 1<<20, 'k' => 1<<10];
	return intval($ini_v) * ($s[strtolower(substr($ini_v,-1))] ?: 1);
}
$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
?>
<!DOCTYPE html>
<html><head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">

<style>
body {font-family: "lucida grande","Segoe UI",Arial, sans-serif; font-size: 14px;width:1024;padding:1em;margin:0;}
th {font-weight: normal; color: #1F75CC; background-color: #F0F9FF; padding:.5em 1em .5em .2em;
	text-align: left;cursor:pointer;user-select: none;}
th .indicator {margin-left: 6px }
thead {border-top: 1px solid #82CFFA; border-bottom: 1px solid #96C4EA;border-left: 1px solid #E7F2FB;
	border-right: 1px solid #E7F2FB; }
#top {height:52px;}
#mkdir {display:inline-block;float:right;padding-top:16px;}
label { display:block; font-size:11px; color:#555;}
#file_drop_target {width:500px; padding:12px 0; border: 4px dashed #ccc;font-size:12px;color:#ccc;
	text-align: center;float:right;margin-right:20px;}
#file_drop_target.drag_over {border: 4px dashed #96C4EA; color: #96C4EA;}
#upload_progress {padding: 4px 0;}
#upload_progress .error {color:#a00;}
#upload_progress > div { padding:3px 0;}
.no_write #mkdir, .no_write #file_drop_target {display: none}
.progress_track {display:inline-block;width:200px;height:10px;border:1px solid #333;margin: 0 4px 0 10px;}
.progress {background-color: #82CFFA;height:10px; }
footer {font-size:11px; color:#bbbbc5; padding:4em 0 0;text-align: left;}
footer a, footer a:visited {color:#bbbbc5;}
#breadcrumb { padding-top:34px; font-size:15px; color:#aaa;display:inline-block;float:left;}
#folder_actions {width: 50%;float:right;}
a, a:visited { color:#00c; text-decoration: none}
a:hover {text-decoration: underline}
.sort_hide{ display:none;}
table {border-collapse: collapse;width:100%;}
thead {max-width: 1024px}
td { padding:.2em 1em .2em .2em; border-bottom:1px solid #def;height:30px; font-size:12px;white-space: nowrap;}
td.first {font-size:14px;white-space: normal;}
td.empty { color:#777; font-style: italic; text-align: center;padding:3em 0;}
.is_dir .size {color:transparent;font-size:0;}
.is_dir .size:before {content: "--"; font-size:14px;color:#333;}
.is_dir .download{visibility: hidden}
a.delete {display:inline-block;
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAADtSURBVHjajFC7DkFREJy9iXg0t+EHRKJDJSqRuIVaJT7AF+jR+xuNRiJyS8WlRaHWeOU+kBy7eyKhs8lkJrOzZ3OWzMAD15gxYhB+yzAm0ndez+eYMYLngdkIf2vpSYbCfsNkOx07n8kgWa1UpptNII5VR/M56Nyt6Qq33bbhQsHy6aR0WSyEyEmiCG6vR2ffB65X4HCwYC2e9CTjJGGok4/7Hcjl+ImLBWv1uCRDu3peV5eGQ2C5/P1zq4X9dGpXP+LYhmYz4HbDMQgUosWTnmQoKKf0htVKBZvtFsx6S9bm48ktaV3EXwd/CzAAVjt+gHT5me0AAAAASUVORK5CYII=) no-repeat scroll 0 2px;
	color:#d00;	margin-left: 15px;font-size:11px;padding:0 0 0 13px;
}
.name {
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAABAklEQVRIie2UMW6DMBSG/4cYkJClIhauwMgx8CnSC9EjJKcwd2HGYmAwEoMREtClEJxYakmcoWq/yX623veebZmWZcFKWZbXyTHeOeeXfWDN69/uzPP8x1mVUmiaBlLKsxACAC6cc2OPd7zYK1EUYRgGZFkG3/fPAE5fIjcCAJimCXEcGxKnAiICERkSIcQmeVoQhiHatoWUEkopJEkCAB/r+t0lHyVN023c9z201qiq6s2ZYA9jDIwx1HW9xZ4+Ihta69cK9vwLvsX6ivYf4FGIyJj/rg5uqwccd2Ar7OUdOL/kPyKY5/mhZJ53/2asgiAIHhLYMARd16EoCozj6EzwCYrrX5dC9FQIAAAAAElFTkSuQmCC) no-repeat scroll 0px 12px;
	padding:15px 0 10px 40px;
}
.is_dir .name {
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAADdgAAA3YBfdWCzAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAI0SURBVFiF7Vctb1RRED1nZu5977VQVBEQBKZ1GCDBEwy+ISgCBsMPwOH4CUXgsKQOAxq5CaKChEBqShNK222327f79n0MgpRQ2qC2twKOGjE352TO3Jl76e44S8iZsgOww+Dhi/V3nePOsQRFv679/qsnV96ehgAeWvBged3vXi+OJewMW/Q+T8YCLr18fPnNqQq4fS0/MWlQdviwVqNpp9Mvs7l8Wn50aRH4zQIAqOruxANZAG4thKmQA8D7j5OFw/iIgLXvo6mR/B36K+LNp71vVd1cTMR8BFmwTesc88/uLQ5FKO4+k4aarbuPnq98mbdo2q70hmU0VREkEeCOtqrbMprmFqM1psoYAsg0U9EBtB0YozUWzWpVZQgBxMm3YPoCiLpxRrPaYrBKRSUL5qn2AgFU0koMVlkMOo6G2SIymQCAGE/AGHRsWbCRKc8VmaBN4wBIwkZkFmxkWZDSFCwyommZSABgCmZBSsuiHahA8kA2iZYzSapAsmgHlgfdVyGLTFg3iZqQhAqZB923GGUgQhYRVElmAUXIGGVgedQ9AJJnAkqyClCEkkfdM1Pt13VHdxDpnof0jgxB+mYqO5PaCSDRIAbgDgdpKjtmwm13irsnq4ATdKeYcNvUZAt0dg5NVwEQFKrJlpn45lwh/LpbWdela4K5QsXEN61tytWr81l5YSY/n4wdQH84qjd2J6vEz+W0BOAGgLlE/AMAPQCv6e4gmWYC/QF3d/7zf8P/An4AWL/T1+B2nyIAAAAASUVORK5CYII=) no-repeat scroll 0px 10px;
	padding:15px 0 10px 40px;
}
.download {
	background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB2klEQVR4nJ2ST2sTQRiHn5mdmj92t9XmUJIWJGq9NHrRgxQiCtqbl97FqxgaL34CP0FD8Qv07EHEU0Ew6EXEk6ci8Q9JtcXEkHR3k+zujIdUqMkmiANzmJdnHn7vzCuIWbe291tSkvhz1pr+q1L2bBwrRgvFrcZKKinfP9zI2EoKmm7Azstf3V7fXK2Wc3ujvIqzAhglwRJoS2ImQZMEBjgyoDS4hv8QGHA1WICvp9yelsA7ITBTIkwWhGBZ0Iv+MUF+c/cB8PTHt08snb+AGAACZDj8qIN6bSe/uWsBb2qV24/GBLn8yl0plY9AJ9NKeL5ICyEIQkkiZenF5XwBDAZzWItLIIR6LGfk26VVxzltJ2gFw2a0FmQLZ+bcbo/DPbcd+PrDyRb+GqRipbGlZtX92UvzjmUpEGC0JgpC3M9dL+qGz16XsvcmCgCK2/vPtTNzJ1x2kkZIRBSivh8Z2Q4+VkvZy6O8HHvWyGyITvA1qndNpxfguQNkc2CIzM0xNk5QLedCEZm1VKsf2XrAXMNrA2vVcq4ZJ4DhvCSAeSALXASuLBTW129U6oPrT969AK4Bq0AeWARs4BRgieMUEkgDmeO9ANipzDnH//nFB0KgAxwATaAFeID5DQNatLGdaXOWAAAAAElFTkSuQmCC) no-repeat scroll 0px 5px;
	padding:4px 0 4px 20px;
}
.rename{
    background: url(data:image/png;base64,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);
    padding:15px 0 10px 40px;
    color: gray;
}
</style>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script>
(function($){
	$.fn.tablesorter = function() {
		var $table = this;
		this.find('th').click(function() {
			var idx = $(this).index();
			var direction = $(this).hasClass('sort_asc');
			$table.tablesortby(idx,direction);
		});
		return this;
	};
	$.fn.tablesortby = function(idx,direction) {
		var $rows = this.find('tbody tr');
		function elementToVal(a) {
			var $a_elem = $(a).find('td:nth-child('+(idx+1)+')');
			var a_val = $a_elem.attr('data-sort') || $a_elem.text();
			return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
		}
		$rows.sort(function(a,b){
			var a_val = elementToVal(a), b_val = elementToVal(b);
			return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
		})
		this.find('th').removeClass('sort_asc sort_desc');
		$(this).find('thead th:nth-child('+(idx+1)+')').addClass(direction ? 'sort_desc' : 'sort_asc');
		for(var i =0;i<$rows.length;i++)
			this.append($rows[i]);
		this.settablesortmarkers();
		return this;
	}
	$.fn.retablesort = function() {
		var $e = this.find('thead th.sort_asc, thead th.sort_desc');
		if($e.length)
			this.tablesortby($e.index(), $e.hasClass('sort_desc') );

		return this;
	}
	$.fn.settablesortmarkers = function() {
		this.find('thead th span.indicator').remove();
		this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
		this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
		return this;
	}
})(jQuery);
$(function(){
	var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
	var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
	var $tbody = $('#list');
	$(window).on('hashchange',list).trigger('hashchange');
	$('#table').tablesorter();

	$('#table').on('click','.delete',function(data) {
		$.post("",{'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
			list();
		},'json');
		return false;
	});

	$('#mkdir').submit(function(e) {
		var hashval = decodeURIComponent(window.location.hash.substr(1)),
			$dir = $(this).find('[name=name]');
		e.preventDefault();
		$dir.val().length && $.post('?',{'do':'mkdir',name:$dir.val(),xsrf:XSRF,file:hashval},function(data){
			list();
		},'json');
		$dir.val('');
		return false;
	});
<?php if($allow_upload): ?>
	// file upload stuff
	$('#file_drop_target').on('dragover',function(){
		$(this).addClass('drag_over');
		return false;
	}).on('dragend',function(){
		$(this).removeClass('drag_over');
		return false;
	}).on('drop',function(e){
		e.preventDefault();
		var files = e.originalEvent.dataTransfer.files;
		$.each(files,function(k,file) {
			uploadFile(file);
		});
		$(this).removeClass('drag_over');
	});
	$('input[type=file]').change(function(e) {
		e.preventDefault();
		$.each(this.files,function(k,file) {
			uploadFile(file);
		});
	});


	function uploadFile(file) {
		var folder = decodeURIComponent(window.location.hash.substr(1));

		if(file.size > MAX_UPLOAD_SIZE) {
			var $error_row = renderFileSizeErrorRow(file,folder);
			$('#upload_progress').append($error_row);
			window.setTimeout(function(){$error_row.fadeOut();},5000);
			return false;
		}

		var $row = renderFileUploadRow(file,folder);
		$('#upload_progress').append($row);
		var fd = new FormData();
		fd.append('file_data',file);
		fd.append('file',folder);
		fd.append('xsrf',XSRF);
		fd.append('do','upload');
		var xhr = new XMLHttpRequest();
		xhr.open('POST', '?');
		xhr.onload = function() {
			$row.remove();
    		list();
  		};
		xhr.upload.onprogress = function(e){
			if(e.lengthComputable) {
				$row.find('.progress').css('width',(e.loaded/e.total*100 | 0)+'%' );
			}
		};
	    xhr.send(fd);
	}
	function renderFileUploadRow(file,folder) {
		return $row = $('<div/>')
			.append( $('<span class="fileuploadname" />').text( (folder ? folder+'/':'')+file.name))
			.append( $('<div class="progress_track"><div class="progress"></div></div>')  )
			.append( $('<span class="size" />').text(formatFileSize(file.size)) )
	};
	function renderFileSizeErrorRow(file,folder) {
		return $row = $('<div class="error" />')
			.append( $('<span class="fileuploadname" />').text( 'Error: ' + (folder ? folder+'/':'')+file.name))
			.append( $('<span/>').html(' file size - <b>' + formatFileSize(file.size) + '</b>'
				+' exceeds max upload size of <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>')  );
	}
<?php endif; ?>
	function list() {
		var hashval = window.location.hash.substr(1);
		$.get('?do=list&file='+ hashval,function(data) {
			$tbody.empty();
			$('#breadcrumb').empty().html(renderBreadcrumbs(hashval));
			if(data.success) {
				$.each(data.results,function(k,v){
					$tbody.append(renderFileRow(v));
				});
				!data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td></tr>')
				data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
			} else {
				console.warn(data.error.msg);
			}
			$('#table').retablesort();
		},'json');
	}
	function renderFileRow(data) {
		var $link = $('<a class="name" />')
			.attr('href', data.is_dir ? '#' + encodeURIComponent(data.path) : './' + data.path)
			.text(data.name);
		var allow_direct_link = <?php echo $allow_direct_link?'true':'false'; ?>;
        	if (!data.is_dir && !allow_direct_link)  $link.css('pointer-events','none');
		var $dl_link = $('<a/>').attr('href','?do=download&file='+ encodeURIComponent(data.path))
			.addClass('download').text('download');

		//link for rename file
		var $rn_link = $('<a/>').attr('href','?do=rename&file='+encodeURIComponent(data.path)).addClass('rename').text('rename');

		var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').text('delete');
		var perms = [];
		if(data.is_readable) perms.push('read');
		if(data.is_writable) perms.push('write');
		if(data.is_executable) perms.push('exec');
		var $html = $('<tr />')
			.addClass(data.is_dir ? 'is_dir' : '')
			.append( $('<td class="first" />').append($link) )
			.append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
				.html($('<span class="size" />').text(formatFileSize(data.size))) )
			.append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
			.append( $('<td/>').text(perms.join('+')) )
			.append( $('<td/>').append($dl_link).append($rn_link).append( data.is_deleteable ? $delete_link : '') )
		return $html;
	}
	function renderBreadcrumbs(path) {
		var base = "",
			$html = $('<div/>').append( $('<a href=#>Home</a></div>') );
		$.each(path.split('%2F'),function(k,v){
			if(v) {
				var v_as_text = decodeURIComponent(v);
				$html.append( $('<span/>').text(' ▸ ') )
					.append( $('<a/>').attr('href','#'+base+v).text(v_as_text) );
				base += v + '%2F';
			}
		});
		return $html;
	}
	function formatTimestamp(unix_timestamp) {
		var m = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
		var d = new Date(unix_timestamp*1000);
		return [m[d.getMonth()],' ',d.getDate(),', ',d.getFullYear()," ",
			(d.getHours() % 12 || 12),":",(d.getMinutes() < 10 ? '0' : '')+d.getMinutes(),
			" ",d.getHours() >= 12 ? 'PM' : 'AM'].join('');
	}
	function formatFileSize(bytes) {
		var s = ['bytes', 'KB','MB','GB','TB','PB','EB'];
		for(var pos = 0;bytes >= 1000; pos++,bytes /= 1024);
		var d = Math.round(bytes*10);
		return pos ? [parseInt(d/10),".",d%10," ",s[pos]].join('') : bytes + ' bytes';
	}
})

</script>
</head><body>
<div id="top">
   <?php if($allow_create_folder): ?>
	<form action="?" method="post" id="mkdir" />
		<label for=dirname>Create New Folder</label><input id=dirname type=text name=name value="" />
		<input type="submit" value="create" />
	</form>

   <?php endif; ?>

   <?php if($allow_upload): ?>

	<div id="file_drop_target">
		Drag Files Here To Upload
		<b>or</b>
		<input type="file" multiple />
	</div>
   <?php endif; ?>
	<div id="breadcrumb">&nbsp;</div>
</div>

<div id="upload_progress"></div>
<table id="table"><thead><tr>
	<th>Name</th>
	<th>Size</th>
	<th>Modified</th>
	<th>Permissions</th>
	<th>Actions</th>
</tr></thead><tbody id="list">

</tbody></table>
<footer>simple php filemanager by <a href="https://github.com/jcampbell1">jcampbell1</a></footer>
</body></html>
