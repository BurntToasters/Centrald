/**
 * Release manifests keep a `.yml` filename for the public feed contract, but
 * the body is pretty-printed JSON (JSON is a YAML 1.2 subset). CDN sync must
 * parse that JSON rather than a `channel: value` YAML line.
 */
export function manifestChannel(body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new Error("Release manifest is not valid JSON.", { cause: error });
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Release manifest is missing a channel field.");
  }
  if (typeof parsed.channel !== "string" || parsed.channel.trim() === "") {
    throw new Error("Release manifest is missing a channel field.");
  }
  return parsed.channel;
}

export function assertManifestChannel(body, expectedChannel) {
  const channel = manifestChannel(body);
  if (channel !== expectedChannel) {
    throw new Error(
      `Release manifest channel is ${channel}, expected ${expectedChannel}; refusing to upload to the wrong CDN prefix.`,
    );
  }
}
