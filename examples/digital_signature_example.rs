//! Example: Digital signatures with rust-pdf
//!
//! This example demonstrates how to sign PDF documents using X.509 certificates.
//!
//! # Prerequisites
//!
//! Generate a self-signed certificate for testing:
//! ```bash
//! # Generate private key
//! openssl genrsa -out private_key.pem 2048
//!
//! # Generate certificate
//! openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365 \
//!     -subj "/CN=Test Signer/O=Example Org/C=US"
//! ```
//!
//! # Running
//!
//! ```bash
//! cargo run --example digital_signature_example --features signatures
//! ```

use rust_pdf::prelude::*;

#[cfg(feature = "signatures")]
use rust_pdf::signatures::{Certificate, DocumentSigner, PrivateKey, SignatureAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("rust-pdf Digital Signature Example");
    println!("===================================\n");

    #[cfg(not(feature = "signatures"))]
    {
        println!("Error: This example requires the 'signatures' feature.");
        println!("Run with: cargo run --example digital_signature_example --features signatures");
        return Ok(());
    }

    #[cfg(feature = "signatures")]
    {
        // Check if certificate files exist
        let cert_path = "certificate.pem";
        let key_path = "private_key.pem";

        if !std::path::Path::new(cert_path).exists()
            || !std::path::Path::new(key_path).exists()
        {
            println!("Certificate files not found. Generating test certificates...\n");
            generate_test_certificates()?;
        }

        // Load certificate and private key
        println!("Loading certificate from: {}", cert_path);
        let cert = Certificate::from_pem_file(cert_path)?;

        println!("Loading private key from: {}", key_path);
        let key = PrivateKey::from_pem_file(key_path)?;

        // Create a PDF document
        println!("\nCreating PDF document...");
        let content = ContentBuilder::new()
            .text("F1", 24.0, 72.0, 750.0, "Digitally Signed Document")
            .text("F2", 14.0, 72.0, 700.0, "This document has been digitally signed.")
            .text("F2", 12.0, 72.0, 660.0, "The signature verifies the document's authenticity")
            .text("F2", 12.0, 72.0, 640.0, "and integrity using X.509 certificates.")
            .text("F2", 12.0, 72.0, 580.0, "Signer: John Doe")
            .text("F2", 12.0, 72.0, 560.0, "Organization: Example Corp")
            .text("F2", 12.0, 72.0, 540.0, "Location: San Francisco, CA")
            .text("F2", 10.0, 72.0, 480.0, "This signature was created using RSA-SHA256 algorithm.");

        let page = PageBuilder::a4()
            .font("F1", Standard14Font::HelveticaBold)
            .font("F2", Standard14Font::Helvetica)
            .content(content)
            .build();

        let doc = DocumentBuilder::new()
            .title("Signed Document")
            .author("John Doe")
            .subject("Digital Signature Example")
            .page(page)
            .build()?;

        // Sign the document
        println!("Signing document...");
        let signed_pdf = DocumentSigner::new(doc)
            .certificate(cert)
            .private_key(key)
            .name("John Doe")
            .reason("Document approval")
            .location("San Francisco, CA")
            .contact_info("john.doe@example.com")
            .algorithm(SignatureAlgorithm::RsaSha256)
            .sign()?;

        // Save the signed PDF
        let output_path = "signed_document.pdf";
        std::fs::write(output_path, &signed_pdf)?;
        println!("\nSigned PDF saved to: {}", output_path);
        println!("File size: {} bytes", signed_pdf.len());

        println!("\nTo verify the signature, open the PDF in Adobe Acrobat Reader");
        println!("or use a PDF signature verification tool.");

        Ok(())
    }
}

#[cfg(feature = "signatures")]
fn generate_test_certificates() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // Generate private key
    println!("Generating RSA private key...");
    let key_output = Command::new("openssl")
        .args(["genrsa", "-out", "private_key.pem", "2048"])
        .output()?;

    if !key_output.status.success() {
        return Err(format!(
            "Failed to generate private key: {}",
            String::from_utf8_lossy(&key_output.stderr)
        )
        .into());
    }

    // Generate self-signed certificate
    println!("Generating self-signed certificate...");
    let cert_output = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-key",
            "private_key.pem",
            "-out",
            "certificate.pem",
            "-days",
            "365",
            "-subj",
            "/CN=Test Signer/O=Example Org/C=US",
        ])
        .output()?;

    if !cert_output.status.success() {
        return Err(format!(
            "Failed to generate certificate: {}",
            String::from_utf8_lossy(&cert_output.stderr)
        )
        .into());
    }

    println!("Test certificates generated successfully.\n");
    Ok(())
}

#[cfg(not(feature = "signatures"))]
fn generate_test_certificates() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
