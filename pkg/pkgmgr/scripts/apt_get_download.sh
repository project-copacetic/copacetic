if [ "$IGNORE_ERRORS" = "true" ]; then
	set -x
else
	set -ex
fi

packages="%s"
apt-get update
apt-get download --no-install-recommends $packages
dpkg --root=/tmp/debian-rootfs --admindir=/tmp/debian-rootfs/var/lib/dpkg --force-all --force-confold --install *.deb
dpkg --root=/tmp/debian-rootfs --configure -a

# create new status.d with contents from status file after updates
STATUS_FILE="/tmp/debian-rootfs/var/lib/dpkg/status"
OUTPUT_DIR="/tmp/debian-rootfs/var/lib/dpkg/status.d"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

package_name=""
package_content=""

while IFS= read -r line || [ -n "$line" ]; do
	if [ -z "$line" ]; then
		# end of a package block
		if [ -n "$package_name" ]; then
				# handle special case for base-files
			if [ "$package_name" = "base-files" ]; then
				output_name="base"
			elif [ "$package_name" = "libssl1.1" || "$package_name" = "libssl" ]; then
				output_name="libssl1.1"
			else 
				output_name="$package_name"
			fi
			# write the collected content to the package file
			echo "$package_content" > "$OUTPUT_DIR/$output_name"
		fi

		# re-set for next package
		package_name=""
		package_content=""
	else
		# add current line to package content
		if [ -z "$package_content" ]; then
			package_content="$line"
		else
			package_content="$package_content
$line"
		fi

		case "$line" in
			"Package:"*)
				# extract package name
				package_name=$(echo "$line" | cut -d' ' -f2)
				;;
			esac
		fi
done < "$STATUS_FILE"

# handle last block if file does not end with a newline
if [ -n "$package_name" ] && [ -n "$package_content" ]; then
	echo "$package_content" > "$OUTPUT_DIR/$package_name"
fi

# delete everything else inside /tmp/debian-rootfs/var/lib/dpkg except status.d
find /tmp/debian-rootfs/var/lib/dpkg -mindepth 1 -maxdepth 1 ! -name "status.d" -exec rm -rf {} +

# write results manifest for validation
for deb in *.deb; do
	dpkg-deb -f "$deb" | grep "^Package:\|^Version:" >> /tmp/debian-rootfs/manifest
done

exit 0
