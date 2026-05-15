import scala.io.Source


@main def exec(cpgFile: String, outFileast: String, outFilepdg: String, outFilecfg: String) = {
  import io.shiftleft.codepropertygraph.Cpg
  import io.shiftleft.semanticcpg.language._
  import java.nio.file.{Files, Paths}

  // Load the code property graph
  importCode(cpgFile)

  // Retrieve the name of the second method
  val secondMethodName = cpg.method.name.take(2).drop(1).l.headOption match {
    case Some(name) => name
    case None =>
      println("No second method found in the codebase.")
      sys.exit(1)
  }

  // Generate the DOT representation of the AST for the specified method
  val astDot = cpg.method(secondMethodName).dotAst.l.mkString("\n")

  // Save the DOT representation to a file
  Files.write(Paths.get(outFileast), astDot.getBytes("UTF-8"))

  println(s"AST DOT representation successfully saved to: $outFileast")

  
  
  // Generate the DOT representation of the PDG for the specified method
  val pdgDot = cpg.method(secondMethodName).dotPdg.l.mkString("\n")

  // Save the DOT representation to a file
  Files.write(Paths.get(outFilepdg), pdgDot.getBytes("UTF-8"))

  println(s"PDG DOT representation successfully saved to: $outFilepdg")
  
  
  
  // Generate the DOT representation of the CFG for the specified method
  val cfgDot = cpg.method(secondMethodName).dotCfg.l.mkString("\n")

  // Save the DOT representation to a file
  Files.write(Paths.get(outFilecfg), cfgDot.getBytes("UTF-8"))

  println(s"CFG DOT representation successfully saved to: $outFilecfg")

}
