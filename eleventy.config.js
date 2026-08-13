export default function (eleventyConfig) {
  eleventyConfig.addPassthroughCopy({ "public": "." });
  eleventyConfig.addPassthroughCopy("src/css");
  eleventyConfig.addPassthroughCopy("src/js");

  // One cache-busting token per build, so asset links stop being hand-bumped.
  eleventyConfig.addGlobalData("assetv", Date.now().toString(36));

  eleventyConfig.addFilter("toISOString", (date) => {
    return new Date(date).toISOString().split("T")[0];
  });

  eleventyConfig.addFilter("find", (arr, key, val) => {
    if (!Array.isArray(arr)) return null;
    return arr.find(item => item[key] === val) || null;
  });

  eleventyConfig.addFilter("capitalize", (str) => {
    if (!str) return "";
    return str.charAt(0).toUpperCase() + str.slice(1);
  });

  return {
    dir: {
      input: "src",
      output: "_site",
      includes: "_includes",
      data: "_data",
    },
  };
}
